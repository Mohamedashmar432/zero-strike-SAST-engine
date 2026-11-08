<?php

namespace App\Http\Controllers;

use App\Services\Helpers;
use Illuminate\Http\Request;

class ToolController extends Controller
{
    public function ping(Request $request)
    {
        $output = shell_exec('ping -c 1 ' . $request->input('host'));
        return response($output);
    }

    public function pingSafe(Request $request)
    {
        $output = shell_exec('ping -c 1 ' . escapeshellarg($request->input('host')));
        return response($output);
    }

    public function uptime()
    {
        return response(Helpers::uptime() . Helpers::diskUsage());
    }

    public function convert(Request $request)
    {
        exec('convert ' . $request->input('file') . ' -resize 200x200 /tmp/thumb.png', $out);
        return response()->json($out);
    }

    public function prefs(Request $request)
    {
        $prefs = unserialize(base64_decode($request->cookie('prefs')));
        return response()->json($prefs);
    }

    public function prefsSafe(Request $request)
    {
        $prefs = json_decode(base64_decode($request->cookie('prefs')), true);
        return response()->json($prefs);
    }
}
