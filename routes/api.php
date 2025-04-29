<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use App\Models\User;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Route;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;

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








// EMAIL
Route::get('/email/verify/{id}/{hash}', function ($id, $hash) {
    $user = User::findOrFail($id);

    if (! hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
        abort(403, 'Invalid verification link.');
    }

    if (! $user->hasVerifiedEmail()) {
        $user->markEmailAsVerified();
        event(new Verified($user));
    }

    return redirect('http://127.0.0.1:5501/home.html'); // Redirect to your frontend
})->middleware('signed')->name('verification.verify');










