<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

// ZS-PHP-034 look-alike: bindings and the query builder.
class UserSafeController extends Controller
{
    public function find(Request $request)
    {
        $rows = DB::select('SELECT id, name FROM users WHERE email = ?', [$request->input('email')]);
        return response()->json($rows);
    }

    public function search(Request $request)
    {
        $users = User::whereRaw('name LIKE ?', ['%' . $request->query('q') . '%'])->get();
        $more = User::where('name', 'like', '%' . $request->query('q') . '%')->get();
        return view('users.index', ['users' => $users, 'more' => $more]);
    }
}
