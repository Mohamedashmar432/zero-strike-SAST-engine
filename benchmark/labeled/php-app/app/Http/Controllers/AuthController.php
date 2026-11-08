<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    private const ALLOWED_NEXT = ['/dashboard', '/notes', '/settings'];

    public function next(Request $request)
    {
        return redirect($request->query('next'));
    }

    public function nextSafe(Request $request)
    {
        $next = $request->query('next');
        if (!in_array($next, self::ALLOWED_NEXT, true)) {
            $next = '/dashboard';
        }
        return redirect($next);
    }

    public function login(Request $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return redirect()->route('login');
        }
        $token = bin2hex(random_bytes(16));
        setcookie('remember', $token, time() + 86400, '/');
        return redirect()->route('home');
    }

    public function loginSecureCookie(Request $request)
    {
        $token = bin2hex(random_bytes(16));
        setcookie('remember', $token, [
            'expires' => time() + 86400,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        return redirect()->route('home');
    }
}
