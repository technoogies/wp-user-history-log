/**
 * User History Logging Admin JavaScript
 */
(function ($) {
    'use strict';

    $(document).ready(function () {
        initLoadMore();
        initChangeUsername();
        initClearHistory();
    });

    const i18n = userHistoryData.i18n || {};

    /**
     * Initialize load more functionality
     */
    function initLoadMore() {
        const $loadMoreBtn = $('#user-history-load-more');
        const $tbody = $('#user-history-tbody');

        if (!$loadMoreBtn.length) {
            return;
        }

        $loadMoreBtn.on('click', function (e) {
            e.preventDefault();

            const $btn = $(this);
            const offset = parseInt($btn.data('offset'), 10);
            const total = parseInt($btn.data('total'), 10);

            if ($btn.hasClass('loading')) {
                return;
            }

            $btn.addClass('loading').text(i18n.loading || 'Loading...');

            $.ajax({
                url: userHistoryData.ajaxUrl,
                type: 'POST',
                dataType: 'json',
                data: {
                    action: 'load_more_user_history',
                    nonce: userHistoryData.nonce,
                    user_id: userHistoryData.userId,
                    offset: offset
                }
            })
            .done(function (response) {
                if (response.success && response.data && response.data.html) {
                    $tbody.append(response.data.html);

                    if (response.data.hasMore) {
                        $btn.data('offset', response.data.newOffset);
                        $btn.removeClass('loading').text(i18n.loadMore || 'Load More');
                    } else {
                        $btn.parent().remove();
                    }
                } else {
                    const message = response && response.data && response.data.message
                        ? response.data.message
                        : i18n.errorGeneric || 'Something went wrong. Please try again.';
                    alert(message);
                    $btn.removeClass('loading').text(i18n.loadMore || 'Load More').prop('disabled', true);
                }
            })
            .fail(function () {
                alert(i18n.errorGeneric || 'Something went wrong. Please try again.');
                $btn.removeClass('loading').text(i18n.loadMore || 'Load More');
            });
        });
    }

    /**
     * Initialize change username functionality
     */
    function initChangeUsername() {
        const $usernameInput = $('#user_login');
        const $usernameWrap = $('.user-user-login-wrap td');

        if (!$usernameInput.length || !$usernameWrap.length) {
            return;
        }

        $usernameWrap.find('.description').remove();

        const currentUsername = $usernameInput.val();

        const $changeLink = $('<a>', {
            href: '#',
            class: 'user-history-change-username-link',
            text: i18n.change || 'Change'
        });

        const $newInput = $('<input type="text" class="regular-text user-history-new-username">')
            .val(currentUsername)
            .attr('autocomplete', 'off');

        const $submitBtn = $('<button>', {
            type: 'button',
            class: 'button user-history-change-username-submit',
            text: i18n.change || 'Change'
        });

        const $cancelBtn = $('<button>', {
            type: 'button',
            class: 'button user-history-change-username-cancel',
            text: i18n.cancel || 'Cancel'
        });

        const $message = $('<span>', {
            class: 'user-history-change-username-message'
        });

        const $form = $('<div>', {
            class: 'user-history-change-username-form',
            css: { display: 'none' }
        }).append($newInput, ' ', $submitBtn, ' ', $cancelBtn, $message);

        $usernameInput.after($changeLink, $form);

        function showForm() {
            $changeLink.hide();
            $usernameInput.hide();
            $form.show();
            $newInput.val($usernameInput.val()).focus();
            $message.hide().text('');
        }

        function hideForm() {
            $form.hide();
            $usernameInput.show();
            $changeLink.show();
            $message.hide().text('');
        }

        $changeLink.on('click', function (e) {
            e.preventDefault();
            showForm();
        });

        $cancelBtn.on('click', function (e) {
            e.preventDefault();
            hideForm();
        });

        $newInput.on('keydown', function (e) {
            if (e.keyCode === 27) {
                hideForm();
            } else if (e.keyCode === 13) {
                e.preventDefault();
                $submitBtn.trigger('click');
            }
        });

        $submitBtn.on('click', function (e) {
            e.preventDefault();

            const newUsername = $newInput.val().trim();
            const oldUsername = $usernameInput.val();

            if (!newUsername) {
                showMessage(i18n.errorGeneric || 'Please enter a username.', false);
                return;
            }

            if (newUsername === oldUsername) {
                hideForm();
                return;
            }

            $submitBtn.prop('disabled', true).text(i18n.pleaseWait || 'Please wait...');
            $cancelBtn.prop('disabled', true);
            $newInput.prop('disabled', true);

            $.ajax({
                url: userHistoryData.ajaxUrl,
                type: 'POST',
                dataType: 'json',
                data: {
                    action: 'user_history_change_username',
                    _ajax_nonce: userHistoryData.changeUsernameNonce,
                    current_username: oldUsername,
                    new_username: newUsername
                }
            })
            .done(function (response) {
                if (response.new_nonce) {
                    userHistoryData.changeUsernameNonce = response.new_nonce;
                }

                if (response.success) {
                    $usernameInput.val(newUsername);
                    showMessage(response.message || i18n.success || 'Username changed.', true);
                    setTimeout(hideForm, 2000);
                } else {
                    const message = response && response.message
                        ? response.message
                        : i18n.errorGeneric || 'Something went wrong. Please try again.';
                    showMessage(message, false);
                }
            })
            .fail(function () {
                showMessage(i18n.errorGeneric || 'Something went wrong. Please try again.', false);
            })
            .always(function () {
                $submitBtn.prop('disabled', false).text(i18n.change || 'Change');
                $cancelBtn.prop('disabled', false);
                $newInput.prop('disabled', false);
            });
        });

        function showMessage(text, isSuccess) {
            $message
                .removeClass('success error')
                .addClass(isSuccess ? 'success' : 'error')
                .text(text)
                .show();
        }
    }

    /**
     * Initialize clear history functionality
     */
    function initClearHistory() {
        const $clearBtn = $('#user-history-clear-log');

        if (!$clearBtn.length) {
            return;
        }

        $clearBtn.on('click', function (e) {
            e.preventDefault();

            if (!confirm(i18n.confirmClear || 'Are you sure you want to clear all history for this user? This cannot be undone.')) {
                return;
            }

            const $btn = $(this);

            if ($btn.hasClass('loading')) {
                return;
            }

            $btn.addClass('loading').prop('disabled', true).text(i18n.clearing || 'Clearing...');

            $.ajax({
                url: userHistoryData.ajaxUrl,
                type: 'POST',
                dataType: 'json',
                data: {
                    action: 'clear_user_history',
                    nonce: userHistoryData.clearHistoryNonce,
                    user_id: userHistoryData.userId
                }
            })
            .done(function (response) {
                if (response.success) {
                    $('#user-history-log').html('<p class="user-history-empty">' + (i18n.emptyLog || 'No changes have been recorded yet.') + '</p>');
                    $('.user-history-count').remove();
                } else {
                    const message = response && response.data && response.data.message
                        ? response.data.message
                        : i18n.errorGeneric || 'Something went wrong. Please try again.';
                    alert(message);
                    $btn.removeClass('loading').prop('disabled', false).text(i18n.clearLog || 'Clear Log');
                }
            })
            .fail(function () {
                alert(i18n.errorGeneric || 'Something went wrong. Please try again.');
                $btn.removeClass('loading').prop('disabled', false).text(i18n.clearLog || 'Clear Log');
            });
        });
    }

})(jQuery);
