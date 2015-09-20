<?php

namespace Prophetz\Anticaptcha;

use Prophetz\Anticaptcha\Client\AbstractClient;
use Prophetz\Curl\Curl;

class Anticaptcha
{
    /** @var Curl */
    private $curl;
    /** @var  AbstractClient */
    private $client;

    public function __construct(Curl $curl, AbstractClient $client)
    {
        $this->curl = $curl;
        $this->client = $client;
    }

    public function decode($imageUrl)
    {
        $captchaImage = $this->curl->init($imageUrl)->exec()->getData();
        $captchaBase64 = base64_encode($captchaImage);
        $captchaKey = $this->recognize($captchaBase64);

        return $captchaKey;
    }

    private function recognize(
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
        $postData = array(
            'method' => 'base64',
            'key' => $this->client->getKey(),
            'body' => $body,
            'phrase' => $is_phrase,
            'regsense' => $is_regsense,
            'numeric' => $is_numeric,
            'min_len' => $min_len,
            'max_len' => $max_len,

        );

        $result = $this->curl
            ->init("http://" . $this->client->getDomain() . "/in.php")
            ->setReturnTransfer(true)
            ->setTimeout(5)
            ->setPostFields($postData)
            ->exec()
            ->getData()
        ;

        if (strpos($result, "ERROR") !== false) {
            if ($is_verbose) echo "server returned error: $result\n";
            return false;
        } else {
            $ex = explode("|", $result);
            $captchaId = $ex[1];
            if ($is_verbose) echo "captcha sent, got captcha ID $captchaId\n";
            $waittime = 0;
            if ($is_verbose) echo "waiting for $rtimeout seconds\n";
            sleep($rtimeout);
            $i = 1;
            while (true) {

                $result = $this->curl
                    ->init("http://" . $this->client->getDomain() . "/res.php?key=" . $this->client->getKey() . '&action=get&id=' . $captchaId)
                    ->exec()
                    ->getData()
                ;

                if (strpos($result, 'ERROR') !== false) {
                    if ($is_verbose) echo "server returned error: $result\n";
                    return false;
                }
                if ($result == "CAPCHA_NOT_READY") {
                    if ($is_verbose) echo "captcha is not ready yet\n";
                    $waittime += $rtimeout;
                    if ($waittime > $mtimeout) {
                        if ($is_verbose) echo "timelimit ($mtimeout) hit\n";
                        break;
                    }
                    if ($is_verbose) echo "waiting for $rtimeout seconds\n";
                    sleep($rtimeout);
                } else {
                    $ex = explode('|', $result);
                    if (trim($ex[0]) == 'OK') return trim($ex[1]);
                }
                $i++;

                if ($i > 6) {
                    echo 'captcha too long';
                    return false;
                }
            }

            return false;
        }
    }

}