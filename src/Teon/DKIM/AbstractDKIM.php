<?php



namespace Teon\DKIM;



abstract class AbstractDKIM {
    
    /**
     *
     *
     */
    protected $_raw;
    
    /**
     *
     *
     */
    protected $_message;
    
    /**
     *
     *
     */
    protected $_params;
    
    /**
     * Initializes required variables and creates/returns a DKIM object
     *
     * @param  string $rawMessage
     * @return DKIM
     * @throws Exception
     */
    public function __construct($rawMessage='', $params=array()) {
        
        $this->_raw = $rawMessage;
        if (!$this->_raw) {
            throw new Exception('No message content provided');
        }
        
        $this->_params = $params;
        
        // to-do: validate RFC-2822 compatible message string
        
        return $this;
    }
    
    /**
     * Canonicalizes a header in either "relaxed" or "simple" modes.
     * Requires an array of headers (header names are part of array values)
     *
     * @param  array $headers
     * @param  string $style
     * @return string
     * @throws Exception
     */
    protected function _canonicalizeHeader($headers=array(), $style="simple") {
        $headers = (array)$headers;
        if (sizeof($headers) == 0) {
            throw new Exception("Attempted to canonicalize empty header array");
        }
        
        $cHeader = '';
        switch ($style) {
            case 'simple':
                $cHeader = implode("\r\n", $headers);
                break;
            case 'relaxed':
            default:
                
                $new = array();
                foreach ($headers as $header) {
                    // split off header name
                    list($name, $val) = explode(':', $header, 2);
                    
                    // lowercase field name
                    $name = trim(strtolower($name));
                    
                    // unfold header values and reduce whitespace
                    $val = trim(preg_replace('/\s+/s', ' ', $val));
                    
                    $new[] = "$name:$val";
                }
                $cHeader = implode("\r\n", $new);
                
                break;
        }
        
        return $cHeader;
    }
    
    /**
     * Canonicalizes a message body in either "relaxed" or "simple" modes.
     * Requires a string containing all body content, with an optional byte-length
     *
     * @param  string $body
     * @param  string $style
     * @param  int $length
     * @return string
     * @throws Exception
     */
    protected function _canonicalizeBody($style='simple', $length=-1) {
        
        $cBody = $this->_getBodyFromRaw();
        
        // trim leading whitespace
        
        if ($cBody == '') {
            return "\r\n";
        }
        
        # [DG]: mangle newlines
        $cBody = str_replace("\r\n","\n",$cBody);
        switch ($style) {
            case 'relaxed':
            default:
                // http://tools.ietf.org/html/rfc4871#section-3.4.4
                // strip whitespace off end of lines &
                // replace whitespace strings with single whitespace
                $cBody = preg_replace('/[ \t]+$/m', '', $cBody);
                $cBody = preg_replace('/[ \t]+/m', ' ', $cBody);
                
                // also perform rules for "simple" canonicalization
                
            case 'simple':
                // http://tools.ietf.org/html/rfc4871#section-3.4.3
                // remove any trailing empty lines
                $cBody = preg_replace('/\n+$/s', '', $cBody);
                break;
        }
        $cBody = str_replace("\n","\r\n",$cBody);
        
        // Add last trailing CRLF
        $cBody .= "\r\n";

        return ($length > 0) ? substr($cBody, 0, $length) : $cBody;
    }
    
    /**
     *
     *
     */
    protected function _getHeaderFromRaw($headerKey, $style='array') {
        
        $raw = (isset($this->_params['headers'])) ?
              str_replace("\r", '', $this->_params['headers'])
            : str_replace("\r", '', $this->_raw);
        $lines = explode("\n", $raw);
        $rawHeaders = array();
        $headerVal = array();
        $counter = 0;
        $on = false;
        foreach ($lines as $line) {
            if ($on === true) {
                if (preg_match('/^\w/', $line) !== 0 || trim($line) == '') {
                    // new header is starting or end of headers
                    $on = false;
                    switch ($style) {
                        case 'array':
                        default:
                            list($key, $val) = explode(':', implode("\r\n", $headerVal), 2);
                            $rawHeaders[$headerKey][$counter] = trim($val);
                            break;
                        case 'string':
                            $rawHeaders[$counter] = implode("\r\n", $headerVal);
                            break;
                    }
                    $headerVal = array();
                    $counter++;
                } else {
                    $headerVal[] = $line;
                }
            }
            if (stripos($line, $headerKey) === 0) {
                $on = true;
                $headerVal[] = $line;
            }
            
            if (trim($line) == '') {
                break;
            }
        }
        
        return $rawHeaders;
        
    }
    
    /**
     *
     *
     */
    protected function _getBodyFromRaw($style='string') {
        
        if (isset($this->_params['body'])) {
            return (string)$this->_params['body'];
        }
        
        // Do not explode by \r\n, rather do it by \n and strip \r from line endif if it is found - see comment below
        $lines = explode("\n", $this->_raw);
        // Jump past all the headers
        $on = false;
        while ($line = array_shift($lines)) {
            // Remove trailing carriage-return if present
            // It might be present if emails are read from Unix maildirs directly instead of via IMAP/POP3
            $line = preg_replace('/\r$/', '', $line);

            if ($on === true && $line != '') {
                break;
            }
            if ($line == '') {
                $on = true;
            }
        }
        
        return implode("\r\n", $lines);
        
    }
    
    /**
     *
     *
     */
    protected static function _hashBody($body, $method='sha1') {

        return base64_encode(hash($method, $body, true));

    }
}
