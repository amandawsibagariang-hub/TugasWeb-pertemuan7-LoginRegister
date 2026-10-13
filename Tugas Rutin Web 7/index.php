<?php

/* =========================================================
   SESSION
========================================================= */

session_start();


/* =========================================================
   KONFIGURASI
========================================================= */

$dataFile = __DIR__ . "/data.json";


/* =========================================================
   MEMBUAT FILE JSON JIKA BELUM ADA
========================================================= */

if (!file_exists($dataFile)) {

    file_put_contents(
        $dataFile,
        json_encode(
            [],
            JSON_PRETTY_PRINT
        )
    );
}


/* =========================================================
   FUNGSI MEMBACA DATA USER
========================================================= */

function getUsers($file)
{
    $json = file_get_contents($file);

    $users = json_decode($json, true);

    if (!is_array($users)) {
        return [];
    }

    return $users;
}


/* =========================================================
   FUNGSI MENYIMPAN DATA USER
========================================================= */

function saveUsers($file, $users)
{
    file_put_contents(
        $file,
        json_encode(
            $users,
            JSON_PRETTY_PRINT
        ),
        LOCK_EX
    );
}


/* =========================================================
   FUNGSI SANITASI OUTPUT
========================================================= */

function e($value)
{
    return htmlspecialchars(
        $value ?? "",
        ENT_QUOTES,
        "UTF-8"
    );
}


/* =========================================================
   FUNGSI REDIRECT
========================================================= */

function redirect($page)
{
    header("Location: ?page=" . $page);
    exit;
}


/* =========================================================
   REMEMBER ME
========================================================= */

if (
    !isset($_SESSION["user"]) &&
    isset($_COOKIE["remember_token"])
) {

    $users = getUsers($GLOBALS["dataFile"]);

    $cookieToken = $_COOKIE["remember_token"];

    foreach ($users as $user) {

        if (
            isset($user["remember_token"]) &&
            hash_equals(
                $user["remember_token"],
                hash("sha256", $cookieToken)
            )
        ) {

            $_SESSION["user"] = [
                "name" => $user["name"],
                "email" => $user["email"]
            ];

            break;
        }
    }
}


/* =========================================================
   PAGE
========================================================= */

$page = $_GET["page"] ?? "login";


/* =========================================================
   JIKA SUDAH LOGIN
========================================================= */

if (
    isset($_SESSION["user"]) &&
    ($page === "login" || $page === "register")
) {

    redirect("dashboard");
}


/* =========================================================
   REGISTER
========================================================= */

if (
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    isset($_POST["register"])
) {

    $name = trim($_POST["name"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    $errors = [];


    /* ---------------------------------------------
       VALIDASI NAMA
    --------------------------------------------- */

    if ($name === "") {

        $errors[] = "Nama wajib diisi.";

    } elseif (strlen($name) < 3) {

        $errors[] = "Nama minimal 3 karakter.";
    }


    /* ---------------------------------------------
       VALIDASI EMAIL
    --------------------------------------------- */

    if ($email === "") {

        $errors[] = "Email wajib diisi.";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $errors[] = "Format email tidak valid.";
    }


    /* ---------------------------------------------
       VALIDASI PASSWORD
    --------------------------------------------- */

    if ($password === "") {

        $errors[] = "Password wajib diisi.";

    } elseif (strlen($password) < 6) {

        $errors[] =
            "Password minimal 6 karakter.";
    }


    /* ---------------------------------------------
       KONFIRMASI PASSWORD
    --------------------------------------------- */

    if ($password !== $confirmPassword) {

        $errors[] =
            "Konfirmasi password tidak sama.";
    }


    /* ---------------------------------------------
       CEK EMAIL DUPLIKAT
    --------------------------------------------- */

    $users = getUsers($dataFile);

    foreach ($users as $user) {

        if (
            strtolower($user["email"]) ===
            strtolower($email)
        ) {

            $errors[] =
                "Email sudah terdaftar.";

            break;
        }
    }


    /* ---------------------------------------------
       JIKA TIDAK ADA ERROR
    --------------------------------------------- */

    if (empty($errors)) {

        $newUser = [

            "id" => uniqid("user_"),

            "name" => $name,

            "email" => strtolower($email),

            "password" =>
                password_hash(
                    $password,
                    PASSWORD_DEFAULT
                ),

            "remember_token" => null,

            "created_at" =>
                date("Y-m-d H:i:s")
        ];


        $users[] = $newUser;

        saveUsers(
            $dataFile,
            $users
        );


        $_SESSION["success"] =
            "Registrasi berhasil! Silakan login.";

        redirect("login");
    }
}


/* =========================================================
   LOGIN
========================================================= */

if (
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    isset($_POST["login"])
) {

    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $remember = isset($_POST["remember"]);

    $errors = [];

    $users = getUsers($dataFile);

    $foundUser = null;


    /* ---------------------------------------------
       VALIDASI EMAIL
    --------------------------------------------- */

    if ($email === "") {

        $errors[] =
            "Email wajib diisi.";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $errors[] =
            "Format email tidak valid.";
    }


    /* ---------------------------------------------
       VALIDASI PASSWORD
    --------------------------------------------- */

    if ($password === "") {

        $errors[] =
            "Password wajib diisi.";
    }


    /* ---------------------------------------------
       CARI USER
    --------------------------------------------- */

    if (empty($errors)) {

        foreach ($users as $user) {

            if (
                strtolower($user["email"]) ===
                strtolower($email)
            ) {

                $foundUser = $user;

                break;
            }
        }


        /* -----------------------------------------
           CEK PASSWORD
        ----------------------------------------- */

        if (
            $foundUser === null ||
            !password_verify(
                $password,
                $foundUser["password"]
            )
        ) {

            $errors[] =
                "Email atau password salah.";
        }
    }


    /* ---------------------------------------------
       LOGIN BERHASIL
    --------------------------------------------- */

    if (empty($errors)) {

        session_regenerate_id(true);


        $_SESSION["user"] = [

            "name" =>
                $foundUser["name"],

            "email" =>
                $foundUser["email"]
        ];


        /* -----------------------------------------
           REMEMBER ME
        ----------------------------------------- */

        if ($remember) {

            $rawToken =
                bin2hex(random_bytes(32));

            $hashedToken =
                hash(
                    "sha256",
                    $rawToken
                );


            foreach ($users as $index => $user) {

                if (
                    strtolower($user["email"]) ===
                    strtolower($foundUser["email"])
                ) {

                    $users[$index]["remember_token"] =
                        $hashedToken;

                    break;
                }
            }


            saveUsers(
                $dataFile,
                $users
            );


            setcookie(
                "remember_token",
                $rawToken,
                [
                    "expires" =>
                        time() + (86400 * 30),

                    "path" => "/",

                    "httponly" => true,

                    "samesite" => "Lax"
                ]
            );
        }


        $_SESSION["success"] =
            "Login berhasil. Selamat datang!";

        redirect("dashboard");
    }
}


/* =========================================================
   LOGOUT
========================================================= */

if ($page === "logout") {

    $users = getUsers($dataFile);


    /* ---------------------------------------------
       HAPUS REMEMBER TOKEN
    --------------------------------------------- */

    if (isset($_SESSION["user"])) {

        $currentEmail =
            $_SESSION["user"]["email"];

        foreach ($users as $index => $user) {

            if (
                strtolower($user["email"]) ===
                strtolower($currentEmail)
            ) {

                $users[$index]["remember_token"] =
                    null;

                break;
            }
        }

        saveUsers(
            $dataFile,
            $users
        );
    }


    /* ---------------------------------------------
       HAPUS COOKIE
    --------------------------------------------- */

    setcookie(
        "remember_token",
        "",
        [
            "expires" => time() - 3600,
            "path" => "/"
        ]
    );


    /* ---------------------------------------------
       HAPUS SESSION
    --------------------------------------------- */

    $_SESSION = [];

    session_destroy();


    header("Location: ?page=login");

    exit;
}


/* =========================================================
   PROTEKSI DASHBOARD
========================================================= */

if (
    $page === "dashboard" &&
    !isset($_SESSION["user"])
) {

    $_SESSION["error"] =
        "Silakan login terlebih dahulu.";

    redirect("login");
}


/* =========================================================
   PESAN SESSION
========================================================= */

$successMessage =
    $_SESSION["success"] ?? "";

$errorMessage =
    $_SESSION["error"] ?? "";

unset($_SESSION["success"]);
unset($_SESSION["error"]);

?>

<!DOCTYPE html>

<html lang="id">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        Login & Register
    </title>


    <style>

        /* =====================================================
           RESET
        ====================================================== */

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }


        /* =====================================================
           BODY
        ====================================================== */

        body {

            font-family:
                Arial,
                Helvetica,
                sans-serif;

            min-height: 100vh;

            background:
                radial-gradient(
                    circle at top left,
                    #27152e,
                    #080c16 45%,
                    #05070d
                );

            color: #ffffff;

            display: flex;

            align-items: center;

            justify-content: center;

            padding: 25px;
        }


        /* =====================================================
           CONTAINER
        ====================================================== */

        .container {

            width: 100%;

            max-width: 450px;
        }


        /* =====================================================
           CARD
        ====================================================== */

        .card {

            background:
                rgba(
                    16,
                    22,
                    37,
                    0.95
                );

            border:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.08
                );

            border-radius: 20px;

            padding: 35px;

            box-shadow:
                0 20px 60px
                rgba(
                    0,
                    0,
                    0,
                    0.45
                );
        }


        /* =====================================================
           LOGO
        ====================================================== */

        .logo {

            text-align: center;

            font-size: 32px;

            font-weight: bold;

            margin-bottom: 8px;
        }


        .logo span {

            color: #ff1688;
        }


        .subtitle {

            text-align: center;

            color: #929db5;

            margin-bottom: 30px;

            line-height: 1.5;
        }


        /* =====================================================
           FORM
        ====================================================== */

        .form-group {

            margin-bottom: 18px;
        }


        label {

            display: block;

            margin-bottom: 8px;

            font-size: 14px;

            color: #dce3f2;
        }


        input {

            width: 100%;

            padding: 14px 15px;

            border-radius: 10px;

            border:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.1
                );

            background: #10172a;

            color: white;

            outline: none;

            font-size: 15px;

            transition: 0.2s;
        }


        input:focus {

            border-color: #ff1688;

            box-shadow:
                0 0 0 3px
                rgba(
                    255,
                    22,
                    136,
                    0.1
                );
        }


        /* =====================================================
           CHECKBOX
        ====================================================== */

        .remember {

            display: flex;

            align-items: center;

            gap: 8px;

            margin-bottom: 20px;

            color: #9da8bf;

            font-size: 14px;
        }


        .remember input {

            width: auto;
        }


        /* =====================================================
           BUTTON
        ====================================================== */

        .btn {

            width: 100%;

            border: none;

            padding: 14px;

            border-radius: 10px;

            background:
                linear-gradient(
                    135deg,
                    #ff1688,
                    #c90068
                );

            color: white;

            font-size: 16px;

            font-weight: bold;

            cursor: pointer;

            transition: 0.2s;
        }


        .btn:hover {

            transform:
                translateY(-2px);

            box-shadow:
                0 10px 25px
                rgba(
                    255,
                    22,
                    136,
                    0.3
                );
        }


        /* =====================================================
           LINK
        ====================================================== */

        .switch {

            text-align: center;

            margin-top: 25px;

            color: #8f9ab2;

            font-size: 14px;
        }


        .switch a {

            color: #ff1688;

            text-decoration: none;

            font-weight: bold;
        }


        .switch a:hover {

            text-decoration: underline;
        }


        /* =====================================================
           ALERT
        ====================================================== */

        .alert {

            padding: 13px 15px;

            border-radius: 10px;

            margin-bottom: 20px;

            font-size: 14px;

            line-height: 1.5;
        }


        .alert-error {

            background:
                rgba(
                    255,
                    77,
                    109,
                    0.12
                );

            border:
                1px solid
                rgba(
                    255,
                    77,
                    109,
                    0.4
                );

            color: #ff758b;
        }


        .alert-success {

            background:
                rgba(
                    34,
                    216,
                    137,
                    0.12
                );

            border:
                1px solid
                rgba(
                    34,
                    216,
                    137,
                    0.4
                );

            color: #4de49c;
        }


        .alert ul {

            padding-left: 20px;
        }


        /* =====================================================
           DASHBOARD
        ====================================================== */

        .dashboard {

            max-width: 700px;

            width: 100%;
        }


        .dashboard-card {

            background:
                rgba(
                    16,
                    22,
                    37,
                    0.95
                );

            border:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.08
                );

            border-radius: 20px;

            padding: 35px;
        }


        .dashboard-title {

            font-size: 32px;

            margin-bottom: 8px;
        }


        .dashboard-title span {

            color: #ff1688;
        }


        .welcome {

            color: #929db5;

            margin-bottom: 30px;
        }


        .user-box {

            background: #10172a;

            border-radius: 15px;

            padding: 25px;

            margin-bottom: 25px;
        }


        .user-box h3 {

            margin-bottom: 18px;

            color: #16d9ff;
        }


        .user-info {

            display: grid;

            grid-template-columns:
                120px 1fr;

            gap: 12px;

            color: #dce3f2;
        }


        .user-info .label {

            color: #8f9ab2;
        }


        .logout-btn {

            display: inline-block;

            background:
                #ff4d6d;

            color: white;

            text-decoration: none;

            padding: 13px 22px;

            border-radius: 10px;

            font-weight: bold;

            transition: 0.2s;
        }


        .logout-btn:hover {

            background: #e83c5a;

            transform:
                translateY(-2px);
        }


        /* =====================================================
           RESPONSIVE
        ====================================================== */

        @media (max-width: 600px) {

            body {

                padding: 15px;
            }


            .card,
            .dashboard-card {

                padding: 25px 20px;
            }


            .logo {

                font-size: 27px;
            }


            .dashboard-title {

                font-size: 27px;
            }


            .user-info {

                grid-template-columns: 1fr;

                gap: 4px;

                margin-bottom: 12px;
            }

        }

    </style>

</head>


<body>


<?php if ($page === "register"): ?>

    <!-- =====================================================
         REGISTER PAGE
    ====================================================== -->

    <div class="container">

        <div class="card">

            <div class="logo">

                📝 <span>Register</span>

            </div>

            <p class="subtitle">

                Buat akun baru untuk
                menggunakan sistem.

            </p>


            <?php if (!empty($errors)): ?>

                <div class="alert alert-error">

                    <ul>

                        <?php foreach ($errors as $error): ?>

                            <li>
                                <?= e($error) ?>
                            </li>

                        <?php endforeach; ?>

                    </ul>

                </div>

            <?php endif; ?>


            <form
                method="POST"
                action="?page=register"
            >

                <div class="form-group">

                    <label for="name">
                        Nama Lengkap
                    </label>

                    <input
                        type="text"
                        id="name"
                        name="name"
                        placeholder="Masukkan nama"
                        value="<?= e($_POST["name"] ?? "") ?>"
                        required
                    >

                </div>


                <div class="form-group">

                    <label for="email">
                        Email
                    </label>

                    <input
                        type="email"
                        id="email"
                        name="email"
                        placeholder="contoh@email.com"
                        value="<?= e($_POST["email"] ?? "") ?>"
                        required
                    >

                </div>


                <div class="form-group">

                    <label for="password">
                        Password
                    </label>

                    <input
                        type="password"
                        id="password"
                        name="password"
                        placeholder="Minimal 6 karakter"
                        required
                    >

                </div>


                <div class="form-group">

                    <label for="confirm_password">
                        Konfirmasi Password
                    </label>

                    <input
                        type="password"
                        id="confirm_password"
                        name="confirm_password"
                        placeholder="Ulangi password"
                        required
                    >

                </div>


                <button
                    type="submit"
                    name="register"
                    class="btn"
                >

                    Daftar Sekarang

                </button>

            </form>


            <div class="switch">

                Sudah punya akun?

                <a href="?page=login">
                    Login di sini
                </a>

            </div>

        </div>

    </div>


<?php elseif ($page === "dashboard"): ?>

    <!-- =====================================================
         DASHBOARD
    ====================================================== -->

    <div class="dashboard">

        <div class="dashboard-card">

            <h1 class="dashboard-title">

                👋 Selamat Datang,
                <span>
                    <?= e($_SESSION["user"]["name"]) ?>
                </span>

            </h1>


            <p class="welcome">

                Kamu berhasil login ke
                sistem Login/Register.

            </p>


            <?php if ($successMessage): ?>

                <div class="alert alert-success">

                    <?= e($successMessage) ?>

                </div>

            <?php endif; ?>


            <div class="user-box">

                <h3>
                    👤 Informasi Pengguna
                </h3>


                <div class="user-info">

                    <div class="label">
                        Nama
                    </div>

                    <div>
                        <?= e($_SESSION["user"]["name"]) ?>
                    </div>


                    <div class="label">
                        Email
                    </div>

                    <div>
                        <?= e($_SESSION["user"]["email"]) ?>
                    </div>


                    <div class="label">
                        Status
                    </div>

                    <div>
                        Aktif / Sudah Login
                    </div>

                </div>

            </div>


            <a
                href="?page=logout"
                class="logout-btn"
            >

                🚪 Logout

            </a>

        </div>

    </div>


<?php else: ?>

    <!-- =====================================================
         LOGIN PAGE
    ====================================================== -->

    <div class="container">

        <div class="card">

            <div class="logo">

                🔐 <span>Login</span>

            </div>

            <p class="subtitle">

                Silakan login untuk masuk
                ke dashboard.

            </p>


            <?php if ($successMessage): ?>

                <div class="alert alert-success">

                    <?= e($successMessage) ?>

                </div>

            <?php endif; ?>


            <?php if ($errorMessage): ?>

                <div class="alert alert-error">

                    <?= e($errorMessage) ?>

                </div>

            <?php endif; ?>


            <?php if (!empty($errors)): ?>

                <div class="alert alert-error">

                    <ul>

                        <?php foreach ($errors as $error): ?>

                            <li>
                                <?= e($error) ?>
                            </li>

                        <?php endforeach; ?>

                    </ul>

                </div>

            <?php endif; ?>


            <form
                method="POST"
                action="?page=login"
            >

                <div class="form-group">

                    <label for="login_email">
                        Email
                    </label>

                    <input
                        type="email"
                        id="login_email"
                        name="email"
                        placeholder="Masukkan email"
                        value="<?= e($_POST["email"] ?? "") ?>"
                        required
                    >

                </div>


                <div class="form-group">

                    <label for="login_password">
                        Password
                    </label>

                    <input
                        type="password"
                        id="login_password"
                        name="password"
                        placeholder="Masukkan password"
                        required
                    >

                </div>


                <label class="remember">

                    <input
                        type="checkbox"
                        name="remember"
                    >

                    Ingat saya selama 30 hari

                </label>


                <button
                    type="submit"
                    name="login"
                    class="btn"
                >

                    Login

                </button>

            </form>


            <div class="switch">

                Belum punya akun?

                <a href="?page=register">
                    Daftar sekarang
                </a>

            </div>

        </div>

    </div>

<?php endif; ?>


</body>

</html>