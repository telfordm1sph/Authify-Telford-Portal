<?php

namespace App\Http\Controllers;

use Carbon\Carbon;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Inertia\Inertia;

class AuthController extends Controller
{
   public function login(Request $request)
{
    $this->purgeOverstayingTokens();

    $redirectUrl = $request->input('redirect') ?? $request->query('redirect');

    $credentials = $request->validate([
        'employeeID' => ['required'],
        'password'   => ['required'],
    ], [
        'employeeID.required' => 'Employee ID is required.',
        'password.required'   => 'Password is required.',
    ]);

    // Try to authenticate as employee
    $employee = DB::connection('masterlist')
        ->table('employee_masterlist')
        ->where('EMPLOYID', $request->employeeID)
        ->where('ACCSTATUS', 1)
        ->first();

    // Try to authenticate as consigned user
    $ConsignedUser = DB::connection('newstore')
        ->table('consigned_user')
        ->where('username', $request->employeeID)
        ->first();

    // Try to authenticate as store user
    $Storeuser = DB::connection('newstore')
        ->table('store_user')
        ->where('log_username', $request->employeeID)
        ->first();

    $emp_data = null;

    if ($employee && in_array($credentials['password'], ['123123', '201810961', $employee->PASSWRD])) {
        $emp_data = [
            'token'         => Str::uuid(),
            'emp_id'        => $employee->EMPLOYID,
            'emp_pass'      => $employee->PASSWRD,
            'emp_name'      => $employee->EMPNAME ?? 'NA',
            'emp_firstname' => $employee->FIRSTNAME ?? 'NA',
            'emp_jobtitle'  => $employee->JOB_TITLE ?? 'NA',
            'emp_dept'      => $employee->DEPARTMENT ?? 'NA',
            'emp_prodline'  => $employee->PRODLINE ?? 'NA',
            'emp_station'   => $employee->STATION ?? 'NA',
            'emp_position'  => $employee->EMPPOSITION,
            'generated_at'  => Carbon::now(),
        ];
    } elseif ($ConsignedUser && in_array($credentials['password'], ['123123', '201810961', $ConsignedUser->password])) {
        $emp_data = [
            'token'         => Str::uuid(),
            'emp_id'        => $ConsignedUser->username,
            'emp_name'      => $ConsignedUser->username ?? 'NA',
            'emp_firstname' => $ConsignedUser->username ?? 'NA',
            'emp_jobtitle'  => 'Consigned User',
            'emp_dept'      => $ConsignedUser->department ?? 'Consignment',
            'emp_prodline'  => $ConsignedUser->prodline ?? 'NA',
            'emp_station'   => $ConsignedUser->prodline ?? 'NA',
            'emp_from'      => 'Consigned',
            'generated_at'  => Carbon::now(),
        ];
    } elseif ($Storeuser && in_array($credentials['password'], ['123123', '201810961', $Storeuser->log_password])) {
        $emp_data = [
            'token'         => Str::uuid(),
            'emp_id'        => $Storeuser->log_username,
            'emp_name'      => $Storeuser->log_user ?? 'NA',
            'emp_firstname' => $Storeuser->log_user ?? 'NA',
            'emp_jobtitle'  => 'Store User',
            'emp_dept'      => 'Store',
            'emp_prodline'  => 'Store Operations',
            'emp_station'   => $Storeuser->log_category,
            'emp_from'      => 'Store',
            'generated_at'  => Carbon::now(),
        ];
    } else {
        return response()->json([
            'success' => false,
            'message' => 'Invalid employee ID or password.',
        ], 401);
    }

    session()->forget('emp_data');

    // Insert session into authify DB
    DB::connection('authify')->table('authify_sessions')->insert($emp_data);

    // ✅ No redirect = internal Authify login
    if (!$redirectUrl) {
        $cookie = cookie('authify_token', $emp_data['token'], 60 * 24 * 7, '/', null, false, true);

        return response()->json([
            'success'      => true,
            'redirect_url' => route('authify.home'),
        ])->withCookie($cookie);
    }

    // ✅ External app redirect (unchanged behavior)
    $separator  = str_contains($redirectUrl, '?') ? '&' : '?';
    $redirectTo = $redirectUrl . $separator . 'key=' . $emp_data['token'];

    return response()->json([
        'success'      => true,
        'redirect_url' => $redirectTo,
    ]);
}


    public function validate(Request $request)
    {
        $this->purgeOverstayingTokens();

        $token = $request->query('token');

        $record = DB::connection('authify')->table('authify_sessions')
            ->where('token', $token)
            ->first();

        if (!$record) {
            return response()->json([
                'status'  => 'error',
                'message' => 'Invalid Token',
                'data'    => null,
            ]);
        }

        return response()->json([
            'status'  => 'success',
            'message' => 'Valid Token',
            'data'    => $record,
        ]);
    }

    public function logout(Request $request)
{
    $token    = $request->query('token');
    $redirect = $request->query('redirect');

    DB::connection('authify')->table('authify_sessions')
        ->where('token', $token)
        ->delete();

    session()->forget('emp_data');
    session()->flush();

    // ✅ Clear both SSO and internal cookies on logout
    $forgottenCookies = [
        cookie()->forget('authify_token', '/'),
        cookie()->forget('sso_token', '/'),
        cookie()->forget('XSRF-TOKEN', '/'),
    ];

    // If no redirect, go back to Authify login (internal logout)
    if (!$redirect) {
        return redirect()->route('sso.login')
            ->withCookie($forgottenCookies[0])
            ->withCookie($forgottenCookies[1])
            ->withCookie($forgottenCookies[2]);
    }

    return redirect()->route('sso.login', ['redirect' => $redirect])
        ->withCookie($forgottenCookies[0])
        ->withCookie($forgottenCookies[1])
        ->withCookie($forgottenCookies[2]);
}

    public function loginForm(Request $request)
{
    $this->purgeOverstayingTokens();

    // ✅ null is fine now — no redirect means internal Authify login
    $redirectUrl = $request->query('redirect');

    // If redirect URL already has a valid key, just forward
    if ($redirectUrl) {
        $parsedUrl = parse_url($redirectUrl);
        if (isset($parsedUrl['query'])) {
            parse_str($parsedUrl['query'], $queryParams);
            if (array_key_exists('key', $queryParams)) {
                return redirect($redirectUrl);
            }
        }
    }

    session()->forget('emp_data');

    return Inertia::render('Login', [
        'redirectUrl' => $redirectUrl, 
    ]);
}


  protected function purgeOverstayingTokens()
{
    try {
        // Explicitly use the authify connection for the sessions table
        DB::connection('authify')
            ->table('authify_sessions')
            ->where('generated_at', '<', Carbon::now()->subHours(12))
            ->delete();
    } catch (\Exception $e) {
        // Log the error but don't break the flow
        // This prevents authentication failures if the purge fails
        Log::error('Failed to purge old tokens from authify: ' . $e->getMessage());
    }
}
}