<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

// ZS-PHP-033: request values joined into paths read through Laravel helpers.
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
}
