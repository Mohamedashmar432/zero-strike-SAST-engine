<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

// ZS-PHP-035: redirect to a request-supplied URL.
class AuthController extends Controller
{
    public function next(Request $request)
    {
        return redirect($request->query('next'));
    }

    public function away(Request $request)
    {
        return redirect()->to($request->input('url'));
    }
}
