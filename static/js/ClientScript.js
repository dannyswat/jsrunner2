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
		}, function (res) {
			console.log(res);
			alert('Unable to retrieve the script list');
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
		}, function (res) {
			console.log(res);
			alert('Unable to retrieve the script ' + template());
			resolve();
		})
	});
}

function deleteFile() {
	return new Promise(function (resolve) {
		if (!template()) return;
		$.ajax({
			url: '/scripts/' + template(),
			method: 'DELETE'
		}).done(function () {
			alert('Deleted successfully!', 'Message');
			resolve();
		}).fail(function (res, err) {
			console.log(res);
			alert(res.responseJSON?.message || err);
			resolve();
		});
	});
}

function save() {
	return new Promise(function (resolve) {
		if (!textarea('scriptKey') || !textarea('scriptName') || !script()) { throw 'Empty data'; }
		if (!(textarea('scriptKey')).match(/^[A-Za-z0-9_-]{1,30}$/)) { throw 'Invalid key!'; }
		if (textarea('scriptName').length > 100) { throw 'Invalid name!'; }
		$.ajax({
			url: '/scripts',
			method: 'POST',
			data: JSON.stringify({ Key: textarea('scriptKey'), Name: textarea('scriptName'), Script: script() }),
			contentType: "application/json; charset=utf-8",
			dataType: "json"
		}).done(function () {
			alert('Saved successfully!', 'Message');
			resolve();
		}).fail(function (res, err) {
			console.log(res);
			alert(res.responseJSON?.message || err);
			resolve();
		});
	});
}

function execute() {
	if (!script()) return;
	try {
		var result = (1, eval)(script()); // return a promise

		if (result && result.then) {
			result.then(function () {
				alert('Executed successfully!', 'Message');
			}).fail(function (resp, err) {
				console.log(err);
				alert(err.message);
			});
		} else {
			alert('Executed successfully!', 'Message');
		}
	} catch (e) {
		console.log(e);
		alert(e);
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