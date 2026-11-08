<?php

namespace App\Services;

class Helpers
{
    /** Runs a maintenance command. Only ever called with constants from this class. */
    public static function run(string $cmd): string
    {
        return (string) shell_exec($cmd);
    }

    public static function diskUsage(): string
    {
        return self::run('df -h /var/www');
    }

    public static function uptime(): string
    {
        return self::run('uptime');
    }
}
