/* global jest, test, describe, it, each, expect */

import { Component as Register, VIEWS } from '../Register';
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';

window.ss = {
  i18n: {
    _t: (key, string) => string,
    inject: (template) => template,
  },
};

let resolveRegistration;
let rejectRegistration;

jest.mock('lib/auth', () => ({
    performRegistration: () => new Promise((resolve, reject) => {
        resolveRegistration = resolve;
        rejectRegistration = reject;
      })
  }));

function makeProps(obj = {}) {
  return {
    method: {
      urlSegment: 'web-authn',
      name: 'Security key',
      description: 'Register using a security key',
      supportLink: 'https://google.com',
      component: 'WebAuthnRegister',
    },
    keyData: {
      foo: 'bar'
    },
    onBack: () => {},
    onCompleteRegistration: () => {},
    ...obj,
  };
}

test('Register back button triggers the onBack callback', () => {
  const onBack = jest.fn();
  const { container } = render(
    <Register {...makeProps({
      onBack
    })}
    />
  );
  const button = container.querySelector('.mfa-action-list__item.btn-secondary');
  expect(button.textContent).toBe('Back');
  fireEvent.click(button);
  expect(onBack).toHaveBeenCalled();
});

test('Register with registrationData available', async () => {
  const onCompleteRegistration = jest.fn();
  const { container } = render(
    <Register {...makeProps({
      onCompleteRegistration
    })}
    />
  );
  let button = container.querySelector('.mfa-action-list__item.btn-primary');
  expect(button.textContent).toBe('Register key');
  fireEvent.click(button);
  await screen.findByText('Waiting');
  resolveRegistration({ some: 'registrationData' });
  await screen.findByText('Key verified');
  button = container.querySelector('.mfa-action-list__item.btn-primary');
  expect(button.textContent).toBe('Complete registration');
  fireEvent.click(button);
  expect(onCompleteRegistration).toHaveBeenCalled();
});

test('Register with registrationData unavailable', async () => {
  const onCompleteRegistration = jest.fn();
  const { container } = render(
    <Register {...makeProps({
      onCompleteRegistration
    })}
    />
  );
  let button = container.querySelector('.mfa-action-list__item.btn-primary');
  expect(button.textContent).toBe('Register key');
  fireEvent.click(button);
  await screen.findByText('Waiting');
  resolveRegistration(null);
  await screen.findByText('Key verified');
  button = container.querySelector('.mfa-action-list__item.btn-primary');
  expect(button.textContent).toBe('Complete registration');
  fireEvent.click(button);
  expect(onCompleteRegistration).not.toHaveBeenCalled();
});

test('Register failure', async () => {
  const { container } = render(<Register {...makeProps()}/>);
  let button = container.querySelector('.mfa-action-list__item.btn-primary');
  expect(button.textContent).toBe('Register key');
  fireEvent.click(button);
  await screen.findByText('Waiting');
  rejectRegistration();
  await screen.findByText('Retry');
  button = container.querySelector('.mfa-action-list__item.btn-primary');
  expect(button.textContent).toBe('Retry');
});

test('Register does not render any actions when a backend error has occurred', () => {
  const { container } = render(
    <Register {...makeProps({
      keyData: null,
      errors: ['I am a unit test']
    })}
    />
  );
  expect(container.querySelector('.mfa-action-list__item')).toBeNull();
});

test('Register renders a disabled register button and a back button when loading', () => {
  const { container } = render(
    <Register {...makeProps({
      keyData: null
    })}
    />
  );
  expect(container.querySelector('.mfa-action-list__item.btn-primary').disabled).toBe(true);
  expect(container.querySelector('.mfa-action-list__item.btn-secondary').disabled).toBe(false);
});

test('Register renders a disabled register button and a back button when ready', () => {
  const { container } = render(<Register {...makeProps()}/>);
  expect(container.querySelector('.mfa-action-list__item.btn-primary').disabled).toBe(false);
  expect(container.querySelector('.mfa-action-list__item.btn-secondary').disabled).toBe(false);
});

test('Register renders disabled registering and back buttons during registration', async () => {
  const { container } = render(<Register {...makeProps()}/>);
  fireEvent.click(container.querySelector('.mfa-action-list__item.btn-primary'));
  await screen.findByText('Waiting');
  expect(container.querySelector('.mfa-action-list__item.btn-primary').disabled).toBe(true);
  expect(container.querySelector('.mfa-action-list__item.btn-secondary').disabled).toBe(true);
});

test('Register renders complete registration button when registration succeeds', async () => {
  const { container } = render(<Register {...makeProps()}/>);
  fireEvent.click(container.querySelector('.mfa-action-list__item.btn-primary'));
  resolveRegistration({ some: 'registrationData' });
  await screen.findByText('Complete registration');
  expect(container.querySelector('.mfa-action-list__item.btn-primary').disabled).toBe(false);
  expect(container.querySelector('.mfa-action-list__item.btn-secondary')).toBeNull();
});

test('Register renders retry and back buttons when registration fails', async () => {
  const { container } = render(<Register {...makeProps()}/>);
  fireEvent.click(container.querySelector('.mfa-action-list__item.btn-primary'));
  rejectRegistration();
  await screen.findByText('Retry');
  const button = container.querySelector('.mfa-action-list__item.btn-primary');
  expect(button.textContent).toBe('Retry');
  expect(button.disabled).toBe(false);
  expect(container.querySelector('.mfa-action-list__item.btn-secondary').disabled).toBe(false);
});

test('Register displays error messages if present', () => {
  const { container } = render(
    <Register {...makeProps({
      keyData: null,
      errors: ['I am a unit test', 'Something went wrong']
    })}
    />
  );
  expect(container.querySelector('.status-message__description').textContent).toBe('I am a unit test, Something went wrong');
});

test('Register displays waiting message when the view is loading', () => {
  const { container } = render(
    <Register {...makeProps({
      keyData: null
    })}
    />
  );
  expect(container.querySelector('.status-message__description').textContent).toBe('Waiting');
});

test('Register displays no message when the view is ready', () => {
  const { container } = render(<Register {...makeProps()}/>);
  expect(container.querySelector('.status-message__description')).toBeNull();
});

test('Register displays waiting message during registration', async () => {
  const { container } = render(<Register {...makeProps()}/>);
  fireEvent.click(container.querySelector('.mfa-action-list__item.btn-primary'));
  await screen.findByText('Waiting');
  expect(container.querySelector('.status-message__description').textContent).toBe('Waiting');
});

test('Register displays complete message when the registration is successful', async () => {
  const { container } = render(<Register {...makeProps()}/>);
  fireEvent.click(container.querySelector('.mfa-action-list__item.btn-primary'));
  resolveRegistration({ some: 'registrationData' });
  await screen.findByText('Key verified');
  expect(container.querySelector('.status-message__description').textContent).toBe('Key verified');
});

test('Register displays error message when the registration fails', async () => {
  const { container } = render(<Register {...makeProps()}/>);
  fireEvent.click(container.querySelector('.mfa-action-list__item.btn-primary'));
  rejectRegistration();
  await screen.findByText('Retry');
  expect(container.querySelector('.status-message__description').textContent).toBe('Something went wrong. Please re-insert your key and try again');
});

test('Register renders the full UI', () => {
  const { container } = render(<Register {...makeProps()}/>);
  expect(container.querySelector('.mfa-registration-container__description')).not.toBeNull();
  expect(container.querySelector('.mfa-registration-container__status')).not.toBeNull();
  expect(container.querySelector('.mfa-registration-container__thumbnail')).not.toBeNull();
  expect(container.querySelector('.mfa-registration-container__actions')).not.toBeNull();
});
