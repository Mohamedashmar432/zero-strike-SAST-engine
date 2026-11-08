<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

// ZS-PHP-001: command injection — the value comes from the Laravel Request.
class ToolsController extends Controller
{
    public function run(Request $request)
    {
        $cmd = $request->input('cmd');
        system($cmd);
    }
}
