<?php
// SSRF family negative fixture (ZS-PHP-013, ZS-PHP-014).
//
// Both sinks send their request to a destination that is a build-time
// constant. What is attacker-controlled is a POST body, a timeout, or a
// stream context -- none of which decide where the request goes, so none of
// them is CWE-918.
//
// Before ZS-PHP-013 was pinned to argument 0 and ZS-PHP-014 to argument 2 and
// the CURLOPT_URL option, "tainted_argument: true" was satisfied by any
// tainted identifier anywhere in the call's subtree, so every one of these
// was reported as SSRF.

const AUDIT_URL = 'https://audit.internal.example.com/v1/events';

function forward_event_curl()
{
    $payload = $_POST['payload'];
    $seconds = (int) $_GET['timeout'];

    $ch = curl_init();
    // The destination is a constant; the option constant here IS CURLOPT_URL
    // but the value is not attacker-influenced.
    curl_setopt($ch, CURLOPT_URL, AUDIT_URL);
    // Argument 2 is tainted, but the option is the request body, not the URL.
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    // Argument 2 is tainted, but a user-chosen timeout is not request forgery.
    curl_setopt($ch, CURLOPT_TIMEOUT, $seconds);

    return curl_exec($ch);
}

function forward_event_stream()
{
    $payload = $_POST['payload'];
    // The tainted value lives in the stream context at argument 2.
    // file_get_contents($filename, $use_include_path, $context) only fetches
    // from $filename, which is a constant here.
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/json',
            'content' => $payload,
        ],
    ]);

    return file_get_contents(AUDIT_URL, false, $context);
}
