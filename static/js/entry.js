jQuery(document).ready( function() {
	
	
	jQuery("#submit_assignment").click( function(e){

		var formdata = {
			name : jQuery('input#form_name').val(),
			url : jQuery('input#form_url').val(),
			description : jQuery('textarea#form_description').val()
		}

		jQuery.ajax({
			url : window.location + '/add_assignment',
			data : formdata,
			dataType : 'JSON',
			type : 'POST',
			success : function(response) {
				
				if (response.status == 'ERROR') {
					alert("All fields are required.");
					jQuery('#form_name').focus();
				} else if (response.status == 'OK') {

					var container = document.createElement("div");
					container.className = "assignment";

					var title = "<strong>"+response.name+"</strong> | just now \
					<p><a href=\""+response.url+"\">"+response.url+"</a></p> \
					<p>" + response.description + "</p><hr/>";

					container.innerHTML = title;

					jQuery('#assignment_container').prepend(container);

					jQuery("#submit_form_container").html("<b>Thanks, your assignment was received. Now displaying on the right.");

				}
				
			},
			error : function(err_response) {
				console.error(err_response);
			}
		});

	})

});