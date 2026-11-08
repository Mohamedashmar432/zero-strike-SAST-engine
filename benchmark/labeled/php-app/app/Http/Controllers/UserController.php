<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function find(Request $request)
    {
        $rows = DB::select("SELECT id, name FROM users WHERE email = '" . $request->input('email') . "'");
        return response()->json($rows);
    }

    public function findSafe(Request $request)
    {
        $rows = DB::select('SELECT id, name FROM users WHERE email = ?', [$request->input('email')]);
        return response()->json($rows);
    }

    public function search(Request $request)
    {
        $users = User::whereRaw("name LIKE '%" . $request->query('q') . "%'")->get();
        return view('users.index', ['users' => $users]);
    }

    public function searchSafe(Request $request)
    {
        $users = User::where('name', 'like', '%' . $request->query('q') . '%')->get();
        return view('users.index', ['users' => $users]);
    }

    public function register(Request $request)
    {
        $user = new User();
        $user->email = $request->input('email');
        $user->password = md5($request->input('password'));
        $user->save();
        return response()->json(['id' => $user->id], 201);
    }

    public function registerSafe(Request $request)
    {
        $user = new User();
        $user->email = $request->input('email');
        $user->password = Hash::make($request->input('password'));
        $user->save();
        return response()->json(['id' => $user->id], 201);
    }
}
