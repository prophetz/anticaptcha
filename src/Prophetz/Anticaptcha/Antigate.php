<?php

namespace Prophetz\Anticaptcha;


class Antigate
{
    protected $container;
    private $client;

    /**
     * @param mixed $client
     */
    public function setClient($client)
    {
        $this->client = $client;
    }

    /**
     * @return mixed
     */
    public function getClient()
    {
        return $this->client;
    }

    public function __construct($container)
    {
        $this->container = $container;
    }

    public function captcha($imageUrl)
    {
        $captcha_base64 = base64_encode(file_get_contents($imageUrl));
        $captcha_key = $this->recognize($captcha_base64);

        return $captcha_key;
    }

    function recognize(
        $body,
        $is_verbose = true,
        $rtimeout = 10,
        $mtimeout = 120,
        $is_phrase = 0,
        $is_regsense = 0,
        $is_numeric = 0,
        $min_len = 0,
        $max_len = 0
    )
    {
        $postdata = array(
            'method'    => 'base64',
            'key'       => $this->getClient()['key'],
            'body'      => $body,
            'phrase'	=> $is_phrase,
            'regsense'	=> $is_regsense,
            'numeric'	=> $is_numeric,
            'min_len'	=> $min_len,
            'max_len'	=> $max_len,

        );
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,             "http://".$this->getClient()['domain']."/in.php");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,     1);
        curl_setopt($ch, CURLOPT_TIMEOUT,             5);
        curl_setopt($ch, CURLOPT_POST,                 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS,         $postdata);
        $result = curl_exec($ch);
        if (curl_errno($ch))
        {
            if ($is_verbose) echo "CURL returned error: ".curl_error($ch)."\n";
            return false;
        }
        curl_close($ch);
        if (strpos($result, "ERROR")!==false)
        {
            if ($is_verbose) echo "server returned error: $result\n";
            return false;
        }
        else
        {
            $ex = explode("|", $result);
            $captcha_id = $ex[1];
            if ($is_verbose) echo "captcha sent, got captcha ID $captcha_id\n";
            $waittime = 0;
            if ($is_verbose) echo "waiting for $rtimeout seconds\n";
            sleep($rtimeout);
            $i=1;
            while(true)
            {
                $result = file_get_contents("http://".$this->getClient()['domain']."/res.php?key=".$this->getClient()['key'].'&action=get&id='.$captcha_id);
                if (strpos($result, 'ERROR')!==false)
                {
                    if ($is_verbose) echo "server returned error: $result\n";
                    return false;
                }
                if ($result=="CAPCHA_NOT_READY")
                {
                    if ($is_verbose) echo "captcha is not ready yet\n";
                    $waittime += $rtimeout;
                    if ($waittime>$mtimeout)
                    {
                        if ($is_verbose) echo "timelimit ($mtimeout) hit\n";
                        break;
                    }
                    if ($is_verbose) echo "waiting for $rtimeout seconds\n";
                    sleep($rtimeout);
                }
                else
                {
                    $ex = explode('|', $result);
                    if (trim($ex[0])=='OK') return trim($ex[1]);
                }
                $i++;

                if ($i>6) {
                    die('captcha too long');
                }
            }

            return false;
        }
    }

}