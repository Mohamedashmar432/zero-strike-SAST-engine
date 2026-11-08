<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

// ZS-PHP-034: request values concatenated into raw SQL.
class UserController extends Controller
{
    public function find(Request $request)
    {
        $rows = DB::select("SELECT id, name FROM users WHERE email = '" . $request->input('email') . "'");
        return response()->json($rows);
    }

    public function search(Request $request)
    {
        $users = User::whereRaw("name LIKE '%" . $request->query('q') . "%'")->get();
        return view('users.index', ['users' => $users]);
    }
}
