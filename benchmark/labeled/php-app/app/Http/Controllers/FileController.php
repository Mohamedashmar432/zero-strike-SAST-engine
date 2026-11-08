<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class FileController extends Controller
{
    public function read(Request $request)
    {
        $name = $request->query('name');
        $body = file_get_contents(storage_path('docs/' . $name));
        return response($body, 200, ['Content-Type' => 'text/plain']);
    }

    public function download(Request $request)
    {
        return response()->download(public_path('exports/' . $request->input('file')));
    }

    public function readConfined(Request $request)
    {
        $root = realpath(storage_path('docs'));
        $name = basename($request->query('name'));
        $path = realpath($root . DIRECTORY_SEPARATOR . $name);
        if ($path === false || strpos($path, $root) !== 0) {
            abort(404);
        }
        return response(file_get_contents($path), 200, ['Content-Type' => 'text/plain']);
    }
}
