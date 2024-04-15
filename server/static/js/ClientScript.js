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
function output(value) {
	document.getElementById('preview-area').style.display = 'none';
	document.getElementById('output-area').style.display = 'block';
	return textarea('outputText', value);
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

function list() {
	$.getJSON('/scripts/list', function (res) {
		var ddl = document.getElementById('scriptList');
		for (var i in res) {
			var opt = document.createElement('option');
			opt.appendChild(document.createTextNode(res[i].name));
			opt.value = res[i].key;
			ddl.appendChild(opt);
		}
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
	if (!template()) {
		textarea('scriptKey', '');
		textarea('scriptName', '');
		return;
	}
	$.getJSON('/scripts/' + template(), function (res) {
		script(res.script);
		textarea('scriptKey', res.key);
		textarea('scriptName', res.name);
	})
}

function deleteFile() {
	if (!template()) return;
	$.ajax({
		url: '/scripts/' + template(),
		method: 'DELETE'
	}).done(function () {
		window.location = window.location;
	}).fail(function (res) {
		console.log(res);
	});
}

function save() {
	if (!textarea('scriptKey') || !textarea('scriptName') || !script()) { console.log('Empty data'); return; }
	$.ajax({
		url: '/scripts',
		method: 'POST',
		data: JSON.stringify({ Key: textarea('scriptKey'), Name: textarea('scriptName'), Script: script() }),
		contentType: "application/json; charset=utf-8",
		dataType: "json"
	}).done(function (res) {
		window.location = window.location;
	}).fail(function (res) {
		console.log(res);
	});
}

function login() {
	if (!textarea('username') || !textarea('password')) { console.log('Empty data'); return; }
	$.ajax({
		url: '/login',
		data: JSON.stringify({ username: textarea('username'), password: textarea('password') }),
		method: 'POST',
		contentType: "application/json; charset=utf-8",
		dataType: "json"
	}).done(function (res) {
		window.accessToken = res.token;
	}).fail(function (res) {
		console.log(res);
	});
}

function createUser() {
	if (!textarea('username') || !textarea('password')) { console.log('Empty data'); return; }
	$.ajax({
		url: '/register',
		data: JSON.stringify({ username: textarea('username'), password: textarea('password') }),
		method: 'POST',
		contentType: "application/json; charset=utf-8",
		dataType: "json"
	}).done(function (res) {
		login();
	}).fail(function (res) {
		console.log(res);
	});
}

function signout() {
	delete window.accessToken
}

function execute() {
	if (!script()) return;
	try {
		var result = (1, eval)(script()); // return a promise

		if (result && result.then) {
			result.then(function (result) {
			}).fail(function (err) {
				output(err);
			});
		}
	} catch (e) {
		output(e);
	}
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