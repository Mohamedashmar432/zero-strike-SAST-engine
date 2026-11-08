<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

// The helper's parameter only ever receives a constant: no finding.
class VersionController extends Controller
{
    public function show(Request $request)
    {
        return $this->launch('--version');
    }

    private function launch($flag)
    {
        return shell_exec('tool ' . escapeshellarg($flag));
    }
}
