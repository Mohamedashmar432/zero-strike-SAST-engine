<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

// ZS-PHP-033 and ZS-PHP-013 look-alike: basename() and a realpath() prefix check.
class FileSafeController extends Controller
{
    public function read(Request $request)
    {
        $root = realpath(storage_path('docs'));
        $name = basename($request->query('name'));
        $path = realpath($root . DIRECTORY_SEPARATOR . $name);
        if ($path === false || strpos($path, $root) !== 0) {
            abort(404);
        }
        return response(file_get_contents($path), 200, ['Content-Type' => 'text/plain']);
    }

    public function download(Request $request)
    {
        return response()->download(public_path('exports/' . basename($request->input('file'))));
    }
}
