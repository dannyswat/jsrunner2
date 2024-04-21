function textarea(key, value) {
	var txt = document.getElementById(key);
	if (typeof value !== "undefined" && value != null)
		txt.value = value;
	return txt.value;
}

function template() {
	var ddl = document.getElementById('scriptList');
	if (ddl.selectedIndex < 0) return "";
	return ddl.options[ddl.selectedIndex].value;
}

function script(value) {
	return textarea('script', value);
}
function input(value) {
	return textarea('inputText', value);
}
function output(value, append) {
	document.getElementById('preview-area').style.display = 'none';
	document.getElementById('output-area').style.display = 'block';
	return textarea('outputText', append ? textarea('outputText') + value : value);
}

function ifempty(value) {
	document.getElementById('preview-area').style.display = 'none';
	document.getElementById('output-area').style.display = 'block';
	if (!textarea('outputText'))
		return textarea('outputText', value);
}

function preview(value) {
	var area = document.getElementById('preview-area');
	area.style.display = 'block';
	document.getElementById('output-area').style.display = 'none';
	area.innerHTML = value;
}

function list(defValue) {
	return new Promise(function (resolve) {
		$.getJSON('/scripts', function (res) {
			var ddl = document.getElementById('scriptList');
			var origValue = defValue || ddl.options[ddl.selectedIndex].value;
			while (ddl.options.length > 1) ddl.options.remove(1);
			for (var i in res) {
				var opt = document.createElement('option');
				opt.appendChild(document.createTextNode(res[i].name));
				opt.value = res[i].key;
				if (opt.value === origValue) opt.selected = true;
				ddl.appendChild(opt);
			}
			resolve();
		});
	});
}

function clipboard(id) {
	var copyText = document.getElementById(id);

	/* Select the text field */
	copyText.select();

	/* Copy the text inside the text field */
	document.execCommand("copy");
}

function load() {
	return new Promise(function (resolve) {
		if (!template()) {
			textarea('scriptKey', '');
			textarea('scriptName', '');
			resolve();
			return;
		}
		$.getJSON('/scripts/' + template(), function (res) {
			script(res.script);
			textarea('scriptKey', res.key);
			textarea('scriptName', res.name);
			resolve();
		})
	});
}

function deleteFile() {
	return new Promise(function (resolve) {
		if (!template()) return;
		$.ajax({
			url: '/ClientScript/Delete?key=' + template(),
			method: 'DELETE'
		}).done(function () {
			resolve();
		}).fail(function (res) {
			console.log(res);
			alert(res);
			resolve();
		});
	});
}

function save() {
	return new Promise(function (resolve) {
		if (!textarea('scriptKey') || !textarea('scriptName') || !script()) { console.log('Empty data'); return; }
		$.ajax({
			url: '/scripts',
			method: 'POST',
			data: JSON.stringify({ Key: textarea('scriptKey'), Name: textarea('scriptName'), Script: script() }),
			contentType: "application/json; charset=utf-8",
			dataType: "json"
		}).done(function (res) {
			resolve();
		}).fail(function (res) {
			alert(res);
			resolve();
		});
	});
}

function execute() {
	if (!script()) return;
	try {
		var result = (1, eval)(script()); // return a promise

		if (result && result.then) {
			result.then(function (result) {
			}).fail(function (err) {
				console.log(err);
				alert(err);
			});
		}
	} catch (e) {
		console.log(e);
		alert(e);
	}
}

function login(usr, pwd) {
	return new Promise(function (resolve, reject) {
		if ((!usr || !pwd) && (!textarea('username_login') || !textarea('password_login'))) { console.log('Empty data'); return; }
		$.ajax({
			url: '/auth/login',
			data: JSON.stringify({
				username: usr || textarea('username_login'),
				password: pwd || textarea('password_login')
			}),
			method: 'POST',
			contentType: "application/json; charset=utf-8",
			dataType: "json"
		}).done(function (res) {
			window.accessToken = res.token;
			resolve(usr || textarea('username_login'));
		}).fail(function (res) {
			console.log(res);
			reject(res);
		});
	});
}

function createUser() {
	return new Promise(function (resolve, reject) {
		if (!textarea('username') || !textarea('password')) { console.log('Empty data'); return; }
		$.ajax({
			url: '/auth/register',
			data: JSON.stringify({ username: textarea('username'), password: textarea('password') }),
			method: 'POST',
			contentType: "application/json; charset=utf-8",
			dataType: "json"
		}).done(function (res) {
			login(textarea('username'), textarea('password')).then(function (name) {
				resolve(name);
			});
		}).fail(function (res) {
			console.log(res);
			reject(res);
		});
	});
}

function signout() {
	delete window.accessToken
}

$(function () {
	list();

	$('input').blur(function (event) {
		$(event.target).removeClass('is-invalid');
		event.target.checkValidity();
	}).bind('invalid', function (event) {
		$(event.target).addClass('is-invalid');
	});
});