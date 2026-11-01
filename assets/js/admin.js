/**
 * User History Logging Admin JavaScript
 */
(function ($) {
    'use strict';

    $(document).ready(function () {
        placeNicenameField();
        initLoadMore();
        initChangeUsername();
        initClearHistory();
        initClearAllLogs();
        initLockToggle();
    });

    const i18n = userHistoryData.i18n || {};

    /**
     * Move the nicename row under WordPress Nickname.
     */
    function placeNicenameField() {
        const $field = $('.user-history-nicename-wrap');
        const $nickname = $('.user-nickname-wrap');

        if (!$field.length || !$nickname.length) {
            return;
        }

        $field.insertAfter($nickname).addClass('user-history-nicename-placed');
    }

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
                    const emptyMessage = document.createElement('p');
                    emptyMessage.className = 'user-history-empty';
                    emptyMessage.appendChild(
                        document.createTextNode(i18n.emptyLog || 'No changes have been recorded yet.')
                    );
                    const log = document.getElementById('user-history-log');
                    if (log) {
                        while (log.firstChild) {
                            log.removeChild(log.firstChild);
                        }
                        log.appendChild(emptyMessage);
                    }
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

    /**
     * Settings: clear every history row.
     */
    function initClearAllLogs() {
        const $clearBtn = $('#user-history-clear-all-logs');
        const message = document.getElementById('user-history-clear-all-logs-message');

        if (!$clearBtn.length) {
            return;
        }

        $clearBtn.on('click', function (e) {
            e.preventDefault();

            if (!confirm(i18n.confirmClearAll || 'Are you sure you want to clear all history logs? This cannot be undone.')) {
                return;
            }

            const $btn = $(this);

            if ($btn.hasClass('loading')) {
                return;
            }

            setClearAllMessage(message, '');
            $btn.addClass('loading').prop('disabled', true).text(i18n.clearing || 'Clearing...');

            $.ajax({
                url: userHistoryData.ajaxUrl,
                type: 'POST',
                dataType: 'json',
                data: {
                    action: 'user_history_clear_all_logs',
                    nonce: userHistoryData.clearAllLogsNonce
                }
            })
            .done(function (response) {
                if (response.success) {
                    const text = response && response.data && response.data.message
                        ? response.data.message
                        : i18n.success || 'Success.';
                    setClearAllMessage(message, text, true);
                    $btn.removeClass('loading').prop('disabled', true).text(i18n.clearAllLogs || 'Clear All Logs');
                    return;
                }

                const errorText = response && response.data && response.data.message
                    ? response.data.message
                    : i18n.errorGeneric || 'Something went wrong. Please try again.';
                setClearAllMessage(message, errorText, false);
                $btn.removeClass('loading').prop('disabled', false).text(i18n.clearAllLogs || 'Clear All Logs');
            })
            .fail(function () {
                setClearAllMessage(message, i18n.errorGeneric || 'Something went wrong. Please try again.', false);
                $btn.removeClass('loading').prop('disabled', false).text(i18n.clearAllLogs || 'Clear All Logs');
            });
        });
    }

    function initLockToggle() {
        const $btn = $('#user-history-toggle-lock');
        const message = document.getElementById('user-history-lock-message');

        if (!$btn.length) {
            return;
        }

        $btn.on('click', function (e) {
            e.preventDefault();

            const $button = $(this);
            const action = $button.data('lock-action');
            const confirmText = action === 'unlock'
                ? (i18n.confirmUnlock || 'Unlock this account?')
                : (i18n.confirmLock || 'Lock this account? They will be signed out immediately.');

            if (!confirm(confirmText)) {
                return;
            }

            if ($button.hasClass('loading')) {
                return;
            }

            setLockMessage(message, '');
            $button.addClass('loading').prop('disabled', true).text(i18n.locking || 'Working...');

            $.ajax({
                url: userHistoryData.ajaxUrl,
                type: 'POST',
                dataType: 'json',
                data: {
                    action: 'user_history_toggle_lock',
                    nonce: userHistoryData.lockNonce,
                    user_id: $button.data('user-id') || userHistoryData.userId,
                    lock_action: action
                }
            })
            .done(function (response) {
                if (response.success) {
                    const text = response.data && response.data.message
                        ? response.data.message
                        : i18n.success || 'Success.';
                    setLockMessage(message, text, true);
                    const locked = response.data && response.data.isLocked;
                    $button
                        .data('lock-action', locked ? 'unlock' : 'lock')
                        .toggleClass('user-history-lock-button', !locked)
                        .removeClass('loading')
                        .prop('disabled', false)
                        .text(locked ? (i18n.unlockAccount || 'Unlock Account') : (i18n.lockAccount || 'Lock Account'));
                    return;
                }

                const errorText = response && response.data && response.data.message
                    ? response.data.message
                    : i18n.errorGeneric || 'Something went wrong. Please try again.';
                setLockMessage(message, errorText, false);
                $button.removeClass('loading').prop('disabled', false).text(
                    action === 'unlock' ? (i18n.unlockAccount || 'Unlock Account') : (i18n.lockAccount || 'Lock Account')
                );
            })
            .fail(function () {
                setLockMessage(message, i18n.errorGeneric || 'Something went wrong. Please try again.', false);
                $button.removeClass('loading').prop('disabled', false).text(
                    action === 'unlock' ? (i18n.unlockAccount || 'Unlock Account') : (i18n.lockAccount || 'Lock Account')
                );
            });
        });
    }

    function setLockMessage(element, text, isSuccess) {
        if (!element) {
            return;
        }

        element.classList.remove('success', 'error');
        if (isSuccess === true) {
            element.classList.add('success');
        } else if (isSuccess === false) {
            element.classList.add('error');
        }

        while (element.firstChild) {
            element.removeChild(element.firstChild);
        }

        if (text) {
            element.appendChild(document.createTextNode(text));
        }
    }

    function setClearAllMessage(element, text, isSuccess) {
        if (!element) {
            return;
        }

        element.classList.remove('success', 'error');
        if (isSuccess === true) {
            element.classList.add('success');
        } else if (isSuccess === false) {
            element.classList.add('error');
        }

        while (element.firstChild) {
            element.removeChild(element.firstChild);
        }

        if (text) {
            element.appendChild(document.createTextNode(text));
        }
    }

})(jQuery);
