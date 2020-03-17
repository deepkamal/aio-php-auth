<?php
/**
 * User: Deesingh
 * Date: 03/12/19
 * Time: 16:46
 */


class JWTProvider
{

    private const SIGN_ALGORITHM = 'RS256';

    /**
     * Converts and signs array into a JWT string.
     *
     * @param array $payload
     * @param string $key
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function encode(array $payload, string $key)
    {
        $header = ['typ' => 'JWT', 'alg' => self::SIGN_ALGORITHM];

        $headerJson = json_encode($header);
        $segments[] = $this->urlSafeB64Encode($headerJson);

        $payloadJson = json_encode($payload);
        $segments[] = $this->urlSafeB64Encode($payloadJson);

        //now going to use openssl_sign()
        $result = openssl_sign(implode('.', $segments),
            $signature,
            $key,
            'sha256');
        if (false === $result) {
            throw new \RuntimeException('Failed to encrypt value. ' . implode("\n", $this->getSslErrors()));
        }
        $segments[] = $this->urlSafeB64Encode($signature);

        return implode('.', $segments); //PACK THE ARRAY CONTAINING JWT

    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string
     */
    private function urlSafeB64Encode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }


    /**
     * Builds request JWT.
     *
     * @param string $formattableTimeString
     * @param string $issuer
     * @param string $subject
     * @param string $audience
     * @param string $services
     * @return string
     */
    public function buildJWTPayload($formattableTimeString, $issuer, $subject, $audience, $services)
    {

        $data = [
            "exp" => strtotime($formattableTimeString),
            "iss" => $issuer,
            "sub" => $subject,
            "aud" => $audience
        ];

        if (is_array($services)) {
            foreach ($services as &$aService) {
                $data[$aService] = true;
            }
        } else {
            //assuming a single service
            $data[$services] = true;
        }

        return $data;
    }

}

function psvm()
{

    $cl_options = ""
        . "i:"       // Client Id
        . "s:"       // Client Secret
        . "k:"       // Key File path
        . "u:"       // Issuer
        . "b:"       // Subject
        . "a:"       // Audience
        . "c:"       // services
        . "e::";     // expires

    $longopts = array(          //just for reference, not used actually
        "client-id:",
        "client-secret:",
        "key-file:",
        "iss:",
        "sub:",
        "aud:",
        "services:",
        "exp::"
    );

    $show_usage = false;
    $cmdLineOpts = getopt($cl_options);

    if (isset($cmdLineOpts["i"])) {

        $client_id = $cmdLineOpts["i"];
        if (isset($cmdLineOpts["s"])) {

            $client_secret = $cmdLineOpts["s"];
            if (isset($cmdLineOpts["k"])) {
                $key_file = $cmdLineOpts["k"];

                echo "Key file is " . $key_file . "\n";
                if (is_file($key_file) && is_readable($key_file)) {
                    $fHandle = fopen($key_file, "r") or die("Unable to read the key file " . $key_file);
                    $private_key = fread($fHandle, filesize($key_file)) or die("Unable to read the key file " . $key_file);
                    fclose($fHandle);
                    if (isset($cmdLineOpts["u"])) {             //Checking issuer
                        $issuer = $cmdLineOpts["u"];
                        if (isset($cmdLineOpts["b"])) {         //checking subject
                            $subject = $cmdLineOpts["b"];
                            if (isset($cmdLineOpts["a"])) {     //checking audience
                                $audience = $cmdLineOpts["a"];
                                if (isset($cmdLineOpts["c"])) { //checking services

                                    $services = preg_split("/,/", $cmdLineOpts["c"]);

                                    if (isset($cmdLineOpts["e"])) {
                                        $exp_time = $cmdLineOpts["e"];
                                    } else {
                                        echo "exp_time not provided assuming 1 day\n";
                                        $exp_time = '1 Day';
                                    }


                                    $jwtInstance = new JWTProvider();

                                    $curl = curl_init();

                                    $payload = $jwtInstance->buildJWTPayload($exp_time,
                                        $issuer,
                                        $subject,
                                        $audience,
                                        $services);

                                    $jwt = $jwtInstance->encode($payload, $private_key);

                                    echo "JWT Prepared:" . $jwt . "\n\n";

                                    $url = "https://ims-na1.adobelogin.com/ims/exchange/jwt/"; //token auth Endpoint


                                    curl_setopt($curl, CURLOPT_POST, 1);

                                    curl_setopt($curl, CURLOPT_POSTFIELDS, array(
                                        "client_id" => $client_id,
                                        "client_secret" => $client_secret,
                                        "jwt_token" => $jwt,

                                    ));

                                    curl_setopt($curl, CURLOPT_URL, $url);
                                    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

                                    $result = curl_exec($curl);

                                    curl_close($curl);

                                    echo "Result of JWT Call\n\n" . $result . "\n";


                                } else {
                                    echo "Services not provided\n";
                                    $show_usage = true;

                                }
                            } else {
                                echo "Audience not provided\n";
                                $show_usage = true;
                            }
                        } else {
                            echo "Subject not provided\n";
                            $show_usage = true;

                        }
                    } else {
                        echo "Issuer not provided\n";
                        $show_usage = true;

                    }


                } else {
                    echo "Unable to read the key file " . $key_file . '\n';
                }


            } else {
                echo "Key file location not provided\n";
                $show_usage = true;

            }

        } else {
            echo "Client-secret not provided\n";
            $show_usage = true;

        }

    } else {
        echo "Client ID not provided\n";
        $show_usage = true;

    }

    if ($show_usage) {
        echo "Usage:\n  JWTProvider.php -i <client-id> -s <client-secret> -k <key-file> -u <issuer> -b <subject> -a <audience> -c <services comma separated> -e <exp time, default 1 Day>";
    }


}

psvm();
exit(1);