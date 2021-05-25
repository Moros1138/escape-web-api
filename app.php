<?php

if(!defined('ABSPATH'))
    define('ABSPATH', dirname(__FILE__));

require ABSPATH . '/vendor/autoload.php';

class EscapeAPI
{
    
    var $data;
    var $lock;

    public function __construct()
    {
        // try to load our environment variables
        $dotenv = Dotenv\Dotenv::createImmutable(ABSPATH);
        $dotenv->load();
        
        try
        {
            $dotenv->required(['API_KEY', 'TIMEZONE']);
        }
        catch(Exception $e)
        {
            http_response_code(500);
            header('Content-type: application/json');
            echo json_encode([
                "status_code" => 500,
                "message" => $e->getMessage()
            ]);

            exit;
        }
        
        // set the default time zone
        date_default_timezone_set($_ENV['TIMEZONE']);

        // get lock
        $lock = sem_get(202105060417);
        if(!sem_acquire($lock))
        {
            http_response_code(500);
            header('Content-type: application/json');
            echo json_encode([
                'status_code' => 500,
                'message' => 'Failed to acquire lock.'
            ]);

            exit;
        }
        
        $this->Load();

        Flight::map('notFound', [ $this, 'not_found' ]);
        
        // Preflight.. gah!
        Flight::route('OPTIONS *', function() { Flight::json(["status_code" => 200,"message" => "preflight is a bitch!"], 200); });

        Flight::route('GET /count(/@mode(/@submode))', [ $this, 'get_count' ]);
        Flight::route('POST /count/@mode/@submode', [ $this, 'update_count' ]);
        
        Flight::route('GET /scores/@mode', [ $this, 'get_scores' ]);
        Flight::route('POST /scores/@mode', [ $this, 'update_scores' ]);
        Flight::route('DELETE /scores', [ $this, 'delete_scores' ]);

        // header set X-XSS-Protection "1; mode=block"
        header("Access-Control-Max-Age: 1728000");
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET,POST,OPTIONS,DELETE,PUT");
        header("Access-Control-Allow-Headers: DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Authorization");
        header("Access-Control-Allow-Credentials: true");


        Flight::start();
        
        // release lock
        sem_release($lock);
    }
    
    public function not_found()
    {
        Flight::json(["status_code" => 404, "message" => "not found"], 404);
    }

    private function FilterParams(Array& $valid_parameters, $input)
    {
        foreach($valid_parameters as $param)
        {
            if($input == $param)
                return true;
        }
        return false;
    }

    public function get_count($mode, $submode)
    {
        $valid_modes = [ 'normal', 'encore' ];
        $valid_submodes = [ 'main', 'survival', 'time' ];

        if(is_null($mode) && is_null($submode))
        {
            Flight::json($this->data['counts']);
            return;
        }

        if( $this->FilterParams($valid_modes, $mode) &&
            $this->FilterParams($valid_submodes, $submode))
        {
            Flight::json(['type' => "{$mode}/{$submode}", 'count' => $this->data['counts']["{$mode}/{$submode}"]]);
            return;
        }
        
        Flight::json(["status_code" => 400, "message" => "invalid request"]);
    }
    
    public function update_count($mode, $submode)
    {
        // authorization
        $this->AuthOrDie();
        
        $valid_modes = [ 'normal', 'encore' ];
        $valid_submodes = [ 'main', 'survival', 'time' ];

        // $request = Flight::request();
        // $data = $request->data->getData();
        
        if( $this->FilterParams($valid_modes, $mode) &&
            $this->FilterParams($valid_submodes, $submode))
        {
            $this->data['counts']["{$mode}/{$submode}"] += 1;

            $this->Save();

            Flight::json(['type' => "{$mode}/{$submode}", 'count' => $this->data['counts']["{$mode}/{$submode}"]]);
            return;
        }

        Flight::jons(["status_code" => 400, "message" => "invalid request"]);
    }

    public function get_scores($mode)
    {
        Flight::json($this->data['time_scores'][$mode]);
    }

    public function update_scores($mode)
    {
        // authorization
        $this->AuthOrDie();
        
        $request = Flight::request();
        
        if($mode != 'normal' && $mode != 'encore')
        {
            Flight::json(['status_code' => 400, 'message' => 'invalid mode'], 400);
            return;
        }

        // merge existing scores with newly updated scores
        $data = $request->data->getData();

        // ensure required data exists
        if(!isset($data['name']) || !isset($data['time']))
        {
            Flight::json(['status_code' => 400, 'message' => 'invalid data'], 400);
            return;
        }

        // ensure time is of integer type
        if(!is_int($data['time']))
            $data['time'] = intval($data['time']);
        
        $this->data['time_scores'][$mode][] = $data;

        // sort by time ascending
        if(count($this->data['time_scores'][$mode]) > 1)
        {
            usort($this->data['time_scores'][$mode], function($a, $b)
            {
                return ((int)$a['time'] > (int)$b['time']);
            });
        }
    
        // keep the top 10 scores
        $this->data['time_scores'][$mode] = array_splice($this->data['time_scores'][$mode], 0, 10);
        
        // save updated scores
        $this->Save();
    
        Flight::json($this->data['time_scores'][$mode]);
    }

    public function delete_scores()
    {
        $this->AuthOrDie();

        $this->data['time_scores']['normal'] = [];
        $this->data['time_scores']['encore'] = [];
        
        $this->Save();
    }

    private function Sign($headers, $time)
    {
        return sha1($_ENV['API_KEY'] . $time . $headers['USER-AGENT'] . "\nescape");
    }

    private function ParseToken($token)
    {
        $token = str_replace('Bearer ', '', $token);
        $components = explode('.', $token);

        if(count($components) != 2)
            return [false, false];

        return $components;
    }
    
    private function GetHeaders()
    {
        $headers = getallheaders();

        $keys = array_keys($headers);
        foreach($keys as $key)
        {
            $headers[strtoupper($key)] = $headers[$key];
            unset($headers[$key]);
        }
        return $headers;
    }

    private function Auth()
    {
        $headers = $this->GetHeaders();

        // missing required headers
        if(!isset($headers['AUTHORIZAION']) && !isset($headers['USER-AGENT']))
            return false;
        
        list($time, $sign) = $this->ParseToken($headers['AUTHORIZATION']);
    
        if(!$time || !$sign)
            return false;
    
        // timestamp out of range?
        if(abs((time() * 1000) - $time) > 5000)
            return false;
        
        // verify signature
        if($sign != $this->Sign($headers, $time))
            return false;
    
        // if we make it here, we're authorized to continue!
        return true;
    }

    private function AuthOrDie()
    {
        if(!$this->Auth())
        {
            http_response_code(401);
            header('Content-type: application/json');
            echo json_encode([
                'status_code' => 401,
                'message' => 'unauthorized'
            ]);
        }
    }

    private function Load()
    {
        // does file exists?
        if(file_exists(ABSPATH . "/data/data.json"))
        {
            $this->data = json_decode(file_get_contents(ABSPATH . "/data/data.json"), true);
            return;
        }
        
        // default data
        $this->data = [
            'time_scores' => [
                'normal' => [],
                'encore' => []
            ],
            'counts' => [
                'normal/main' => 0,
                'normal/survival' => 0,
                'normal/time' => 0,
                'encore/main' => 0,
                'encore/survival' => 0,
                'encore/time' => 0
            ]
        ];
    }
    
    private function Save()
    {
        file_put_contents(ABSPATH . "/data/data.json", json_encode($this->data));
    }
}

new EscapeAPI();
