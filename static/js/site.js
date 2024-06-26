const encoder = new TextEncoder();

function login(usr, pwd) {
    return new Promise(async function (resolve, reject) {
        if ((!usr || !pwd) && (!textarea('username_login') || !textarea('password_login'))) { console.log('Empty data'); return; }
        try {
            const key = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey", "deriveBits"]);
            const myPublicKey = await window.crypto.subtle.exportKey("raw", key.publicKey)
            const serverPublicKey = await window.crypto.subtle.importKey("raw", fromBase64(window.publicECKey), { name: "ECDH", namedCurve: "P-256" }, true, []);
            const derived = await window.crypto.subtle.deriveKey({ name: "ECDH", namedCurve: "P-256", public: serverPublicKey },
                key.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
            const pwdBytes = encoder.encode(pwd || textarea('password_login'));
            const ivBuf = randomIV();
            const encryptedPwd = await window.crypto.subtle.encrypt({
                name: "AES-GCM", iv: ivBuf
            }, derived, pwdBytes)
            const pwdWithIv = combineArrayBuffer(ivBuf, encryptedPwd);
            $.ajax({
                url: '/auth/login',
                data: JSON.stringify({
                    username: usr || textarea('username_login'),
                    password: base64(pwdWithIv),
                    key: base64(myPublicKey)
                }),
                method: 'POST',
                contentType: "application/json; charset=utf-8",
                dataType: "json",
                xhrFields: { withCredentials: true }
            }).done(function (res) {
                const loggedInName = getCookie('user');
                initUser();
                resolve(loggedInName);
            }).fail(function (res) {
                console.log(res);
                reject(res);
            });
        }
        catch (ex) {
            console.log(ex);
            reject(ex);
        }
    });
}

function loadPublicKey() {
    $.ajax({
        url: '/auth/publickey',
        method: 'GET',
        dataType: 'json'
    }).done(function (res) {
        window.publicECKey = res.key;
    })
}

function createUser() {
    return new Promise(function (resolve, reject) {
        if (!textarea('username') || !textarea('password')) { console.log('Empty data'); return; }
        $.ajax({
            url: '/auth/register',
            data: JSON.stringify({ username: textarea('username'), password: textarea('password') }),
            method: 'POST',
            contentType: "application/json; charset=utf-8"
        }).done(function (res) {
            login(textarea('username'), textarea('password')).then(function (name) {
                resolve(name);
            }).fail(function (res) { console.log(res); reject(res); });
        }).fail(function (res) {
            console.log(res);
            reject(res);
        });
    });
}

function signout() {
    removeCookie('user');
    document.title = document.title.replace(/\[(.*)\]/, '[public]');
    $(document.body).removeClass('loggedin');
}

function loading(button, promise) {
    return new Promise(function (resolve, reject) {
        var orig = $(button).html();
        $(button).prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span><span class="sr-only">Loading...</span>');
        promise().then(function () { $(button).prop('disabled', false).html(orig); resolve(); }).catch(function (res) { $(button).prop('disabled', false).html(orig); reject(res); });
    });
}

function alert(message, title) {
    $('.alerts').html('').append(
        '<div class="toast" role="alert" aria-live="assertive" aria-atomic="true">' +
        '<div class="toast-header">' +
        '<strong class="mr-auto">' + ( title || 'Error') + '</strong>' +
        '<button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close"><span aria-hidden="true">&times;</span></button>' +
        '</div><div class="toast-body">' + message + '</div>');
    $('.toast').toast({ delay: 5000 }).toast('show');
}

function initUser() {
    if (getCookie('user')) {
        document.title = document.title.replace(/\[(.*)\]/, '[' + getCookie('user') + ']');
        $(document.body).addClass('loggedin');
    }
}

function getCookie(name) {
    var value = "; " + document.cookie;
    var parts = value.split("; " + name + "=");
    if (parts.length == 2) return parts.pop().split(";").shift();
}

function removeCookie(name) {
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}

function randomIV() {
    const buf = new ArrayBuffer(12);
    const arr = new Uint8Array(buf);
    crypto.getRandomValues(arr);
    return buf;
}

function base64(bufArray) {
    const arr = new Uint8Array(bufArray);
    const ir = [];
    for (let i = 0; i < arr.byteLength; i++) {
        ir.push(String.fromCharCode(arr[i]))
    }
    return btoa(ir.join(''));
}

function fromBase64(str) {
    const s = atob(str);
    const buf = new ArrayBuffer(s.length);
    const arr = new Uint8Array(buf);

    for (let i = 0; i < s.length; i++) {
        arr[i] = s.charCodeAt(i);
    }
    return buf;
}

function combineArrayBuffer(a, b) {
    aAr = new Uint8Array(a);
    bAr = new Uint8Array(b);
    const buf = new ArrayBuffer(aAr.byteLength + bAr.byteLength);
    ar = new Uint8Array(buf);
    for (let i = 0; i < aAr.length; i++)
        ar[i] = aAr[i];
    for (let i = 0; i < bAr.length; i++)
        ar[aAr.byteLength + i] = bAr[i];
    return buf;
}

loadPublicKey();