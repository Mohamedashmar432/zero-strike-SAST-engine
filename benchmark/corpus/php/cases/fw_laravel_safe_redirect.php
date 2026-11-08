<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

// ZS-PHP-035 look-alike: the destination is checked against an allowlist.
class AuthSafeController extends Controller
{
    private const ALLOWED_NEXT = ['/dashboard', '/notes', '/settings'];

    public function next(Request $request)
    {
        $next = $request->query('next');
        if (!in_array($next, self::ALLOWED_NEXT, true)) {
            $next = '/dashboard';
        }
        return redirect($next);
    }
}
