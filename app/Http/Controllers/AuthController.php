<?php

namespace App\Http\Controllers;


use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Dotenv\Exception\ValidationException;

use function Laravel\Prompts\password;

class AuthController extends Controller
{
    public function login(Request $request)
    {



        //Trim is auto for email and name

        $email = (string) $request->input('email');
        $email = preg_replace('/\s+/', '', trim($email));
        if ($request->email !== $email) {
            return response()->json([
                'message' => 'Email must not contain spaces',
            ], 400);
        }

        $password = (string) $request->input('password');
        $password = preg_replace('/\s+/', '', trim($password));
        if ((string) $request->input('password') !== $password) {
            return response()->json([
                'message' => 'Password must not contain spaces',
            ], 400);
        }


        try {

            // Validate inputs
            $request->validate(
                [
                    'email' => 'required|email',
                    'password' => 'required',
                ],
                [
                    'email.required' => 'The email field is required',
                    'email.email' => 'The email must be a valid email address',
                    'password' => 'The password field is required',
                ]
            );

            // Find user
            $user = User::where('email', $request->email)->first();

            if (! $user || ! Hash::check($request->password, $user->password)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid login details',
                    'error' => 'Data do not match',
                ], 401);
            }

            // Generate API token
            $token = $user->createToken('api-token')->plainTextToken;

            return response()->json([
                'success' => true,
                'message' => 'Success while logging in',
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user,
            ], 200);
        } catch (\Exception $error) {
            return response()->json([
                'success' => false,
                'message' => 'Error while logging in',
                'error' => $error->getMessage(),
            ], 500);
        }
    }




    public function register(Request $request)
    {


        //Trim is auto for email and name

        $email = (string) $request->input('email');
        $email = preg_replace('/\s+/', '', trim($email));
        if ($request->email !== $email) {
            return response()->json([
                'message' => 'Email must not contain spaces',
            ], 400);
        }

        $password = (string) $request->input('password');
        $password = preg_replace('/\s+/', '', trim($password));
        if ((string) $request->input('password') !== $password) {
            return response()->json([
                'message' => 'Password must not contain spaces',
            ], 400);
        }


        try {
            $request->validate(
                [
                    'name' => 'required',
                    'email' => 'required|email|unique:users,email',
                    'password' => 'required',
                ],
                [
                    'name.required' => 'The name field is required',
                    'email.required' => 'The email field is required',
                    'email.email' => 'The email must be a valid email address',
                    'email.unique' => 'The email is already registered',
                    'password.required' => 'The passowrd field is required'
                ]
            );

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            $user->sendEmailVerificationNotification();

            $token = $user->createToken('api-token')->plainTextToken;

            return response()->json([
                'success' => true,
                'message' => 'Success while registering',
                'access_token' => $token,
                'token_type' => 'Bearer',
            ], 201);
        } catch (\Exception $error) {
            return response()->json([
                'success' => false,
                'message' => 'Error while registering',
                'error' => $error->getMessage(),
            ], 500);
        }
    }





    public function updateUser(Request $request)
    {


        //Trim is auto for email and name

        $email = (string) $request->input('email');
        $email = preg_replace('/\s+/', '', trim($email));
        if ($request->email !== $email) {
            return response()->json([
                'message' => 'Email must not contain spaces',
            ], 400);
        }

        $user = $request->user();

        try {
            $request->validate(
                [
                    'name' => 'required',
                    'email' => 'required|email|unique:users,email,' . $user->id,
                ],
                [
                    'name.required' => 'The name field is required',
                    'email.required' => 'The email field is required',
                    'email.email' => 'The email must be a valid email address',
                    'email.unique' => 'The email is already registered',
                ]
            );

            // If the email is being changed, reset verification
            if ($user->email !== $request->email) {
                $user->email = $request->email;
                $user->email_verified_at = null;
                $user->save();
                $user->sendEmailVerificationNotification();
            }

            $user->update($request->only('name', 'email'));

            return response()->json([
                    'message' => 'User updated successfully',
                    'user' => $user
                ],200);
        } catch (\Exception $error) {
            return response()->json([
                'success' => false,
                'message' => 'Error while updating user',
                'error' => $error->getMessage(),
            ], 500);
        }
    }





    public function changePassword(Request $request)
    {

        //Trim is auto for email and name

        $current_password = (string) $request->input('current_password');
        $current_password = preg_replace('/\s+/', '', trim($current_password));
        if ((string) $request->input('current_password') !== $current_password) {
            return response()->json([
                'message' => 'Password must not contain spaces',
            ], 400);
        }

        $new_password = (string) $request->input('new_password');
        $new_password = preg_replace('/\s+/', '', trim($new_password));
        if ((string) $request->input('new_password') !== $new_password) {
            return response()->json([
                'message' => 'Password must not contain spaces',
            ], 400);
        }




        try {
            $request->validate(
                [
                    'current_password' => ['required'],
                    'new_password' => ['required', 'confirmed'],
                ],
                [
                    'current_password.required' => 'The current password field is required',
                    'new_password.required' => 'The new password field is required',
                    'new_password.confirmed' => 'Passwords must match',
                ]
            );

            $user = $request->user();

            if (!Hash::check($request->current_password, $user->password)) {
                return response()->json([
                    'success' => false,
                    'message' => 'The current password is incorrect',
                    'error' => 'Incorrect password',
                ], 401);
            }

            $user->password = Hash::make($request->new_password);
            $user->save();

            return response()->json([
                'success' => true,
                'message' => 'Password changed successfully.'
            ]);
        } catch (\Exception $error) {
            return response()->json([
                'success' => false,
                'message' => 'Error while changing password',
                'error' => $error->getMessage(),
            ], 500);
        }
    }
}
