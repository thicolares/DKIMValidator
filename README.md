# PHP DKIM validator



## Installation

```
composer require teon/dkim
```



## Usage

```php
$msgContent = "...";
$dkimValidator = new \Teon\DKIM\Validator($msgContent);
if (!$dkimValidator->validateBoolean()) {
    throw new Exception("DKIM validation FAILED!");
}
```



# Changelog

See git history :)
