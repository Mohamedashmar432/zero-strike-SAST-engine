<?php

return [
    'status' => ['url' => env('STATUS_URL', 'https://status.example.com')],
    'payments' => [
        'secret' => 'EXAMPLE-NOT-REAL-payments-secret',
    ],
    'mail' => [
        'password' => env('MAIL_PASSWORD'),
    ],
];
