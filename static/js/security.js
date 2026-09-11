function getCSRFToken() {

    const meta = document.querySelector(
        'meta[name="csrf-token"]'
    );

    if (!meta) {

        console.error(
            "Lpdoplayer: CSRF token not found."
        );

        return "";
    }

    return meta.getAttribute("content");
}


document.addEventListener(
    "DOMContentLoaded",
    function () {

        const forms = document.querySelectorAll(
            'form[method="POST"], form[method="post"]'
        );


        forms.forEach(function (form) {

            form.addEventListener(
                "submit",
                function () {

                    let csrfInput =
                        form.querySelector(
                            'input[name="csrf_token"]'
                        );


                    if (!csrfInput) {

                        csrfInput =
                            document.createElement(
                                "input"
                            );

                        csrfInput.type = "hidden";

                        csrfInput.name =
                            "csrf_token";

                        form.appendChild(
                            csrfInput
                        );
                    }


                    csrfInput.value =
                        getCSRFToken();

                }
            );

        });

    }
);