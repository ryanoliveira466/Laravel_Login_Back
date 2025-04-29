<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });


// PROTECTED routes
Route::middleware('auth:sanctum')->group(function () {

    //Notice: GET /user/{user} will catch everything under /user/*.
    //When you request /user/my, Laravel thinks "my" is a {user} parameter!
    //It tries to find a User with ID = "my" — but "my" is not a number — so everything breaks!
    //THAT'S why it only works when you remove Route::resource().

    Route::get('/user/my', [UserController::class, 'my']);
    Route::post('/user/update', [AuthController::class, 'updateUser']);
    Route::post('/user/change-password', [AuthController::class, 'changePassword']);

    
    
});

// PUBLIC routes
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);


// TEST RESTFUL Commands
Route::resource('/user', UserController::class);







