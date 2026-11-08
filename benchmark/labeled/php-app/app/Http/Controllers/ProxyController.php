<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class ProxyController extends Controller
{
    public function fetch(Request $request)
    {
        $content = file_get_contents($request->query('url'));
        return response($content);
    }

    public function webhook(Request $request)
    {
        $response = Http::post($request->input('callback'), ['status' => 'done']);
        return response()->json(['code' => $response->status()]);
    }

    public function rates(Request $request)
    {
        $currency = urlencode($request->query('currency', 'EUR'));
        $response = Http::get('https://api.example.com/v1/rates/' . $currency);
        return response()->json($response->json());
    }

    public function status()
    {
        $response = Http::get(config('services.status.url') . '/health');
        return response()->json($response->json());
    }
}
