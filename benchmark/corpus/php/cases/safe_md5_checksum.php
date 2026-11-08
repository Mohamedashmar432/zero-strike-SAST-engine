<?php
// ZS-PHP-010 look-alike: md5 as an ETag, cache key and file checksum, never
// over a credential.
$etag = md5(file_get_contents('/var/app/public/app.css'));
$cacheKey = md5(json_encode(['page' => 1, 'sort' => 'name']));
$requestId = md5(uniqid());
