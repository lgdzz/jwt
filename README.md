### Install

```
composer require lgdz/jwt
```

### Demo
```php
try {

    $jwt = new Jwt('私钥', '公钥');
    
    //签发token
    $jwt->issue($data, 60);
    
    //验证token
    $jwt->check($token);
    
} catch (\Exception $e) {
    var_dump($e->getMessage());
}
```