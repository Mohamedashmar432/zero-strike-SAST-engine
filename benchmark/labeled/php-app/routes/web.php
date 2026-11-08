<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\FileController;
use App\Http\Controllers\ProxyController;
use App\Http\Controllers\ToolController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::get('/users/find', [UserController::class, 'find']);
Route::get('/users/search', [UserController::class, 'search']);
Route::post('/users', [UserController::class, 'register']);
Route::get('/files/read', [FileController::class, 'read']);
Route::get('/files/download', [FileController::class, 'download']);
Route::get('/proxy/fetch', [ProxyController::class, 'fetch']);
Route::post('/proxy/webhook', [ProxyController::class, 'webhook']);
Route::get('/proxy/rates', [ProxyController::class, 'rates']);
Route::get('/login/next', [AuthController::class, 'next']);
Route::post('/login', [AuthController::class, 'login']);
Route::get('/tools/ping', [ToolController::class, 'ping']);
Route::get('/tools/uptime', [ToolController::class, 'uptime']);
Route::post('/tools/convert', [ToolController::class, 'convert']);
Route::get('/tools/prefs', [ToolController::class, 'prefs']);
