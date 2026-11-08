<?php
namespace App\Services;

// Laravel service class: run() is only ever called with constants from this
// class, and a parameter of a non-entry-point method is not request data.
class Helpers
{
    public static function run(string $cmd): string
    {
        return (string) shell_exec($cmd);
    }

    public static function uptime(): string
    {
        return self::run('uptime');
    }
}
