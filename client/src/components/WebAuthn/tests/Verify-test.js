/* global jest, test, describe, it, each, expect */

import React from 'react';
import { render, fireEvent, screen } from '@testing-library/react';
import Verify from '../Verify';

window.ss = {
  i18n: {
    _t: (key, string) => string,
    inject: (template) => template,
  },
};

function makeProps(obj = {}) {
  return {
    method: {
      urlSegment: 'web-authn',
      name: 'Security key',
      description: 'Verify using a security key',
      supportLink: 'https://google.com',
      component: 'Verify',
      thumbnail: '/foo/bar.jpg',
    },
    onCompleteVerification: () => {},
    ...obj,
  };
}

let resolveVerification;
let rejectVerification;

jest.mock('lib/auth', () => ({
  performVerification: () => new Promise((resolve, reject) => {
    resolveVerification = resolve;
    rejectVerification = reject;
  })
}));

test('Verify retry clears failure state', async () => {
  const { container } = render(<Verify {...makeProps()}/>);
  expect(container.querySelector('.status-message__description').textContent).toBe('Waiting...');
  // verification fetch is sent as soon as the component is rendered
  rejectVerification();
  await screen.findByText('Try again');
  expect(container.querySelector('.status-message__description').textContent).toBe('Something went wrong, please re-insert your key and try again');
  fireEvent.click(container.querySelector('.mfa-action-list__item.btn-primary'));
  expect(container.querySelector('.status-message__description').textContent).toBe('Waiting...');
});

test('Verify performs verification then calls onCompleteVerification on success', async () => {
  // There's code in Verify::startAuth() that does a 1000ms setTimeout as a callback after setting state
  // hence why we have this somewhat convoluted test
  let doResolve;
  const promise = new Promise((resolve) => {
    doResolve = resolve;
  });
  const onCompleteVerification = jest.fn(() => doResolve());
  render(
    <Verify {...makeProps({
      onCompleteVerification
    })}
    />
  );
  resolveVerification();
  await screen.findByText('Logging in...');
  await promise;
  expect(onCompleteVerification).toHaveBeenCalled();
});

test('Verify renders the instructions', () => {
  const { container } = render(<Verify {...makeProps()}/>);
  expect(container.querySelector('.mfa-verification-container__description').textContent).toContain('Use your security key to verify your identity.');
});

test('Verify renders the help link when one is provided', () => {
  const { container } = render(<Verify {...makeProps()}/>);
  expect(container.querySelector('.mfa-verification-container__description').textContent).toContain('How to use security keys');
});

test('Verify renders the help link when one is provided', () => {
  const { container } = render(
    <Verify {...makeProps({
      method: {
        ...makeProps().method,
        supportLink: null,
      }
    })}
    />
  );
  expect(container.querySelector('.mfa-verification-container__description').textContent).not.toContain('How to use security keys');
});

test('Verify handles provided errors as props', () => {
  const { container } = render(
    <Verify {...makeProps({
      errors: ['I am a test', 'Hello world'],
    })}
    />
  );
  expect(container.querySelector('.status-message--error')).not.toBeNull();
  expect(container.querySelector('.status-message__description').textContent).toBe('I am a test, Hello world');
});

test('Verify handles a success state', async () => {
  const { container } = render(<Verify {...makeProps()}/>);
  resolveVerification();
  await screen.findByText('Logging in...');
  expect(container.querySelector('.status-message--success')).not.toBeNull();
});

test('Verify handles a failure state', async () => {
  const { container } = render(<Verify {...makeProps()}/>);
  rejectVerification();
  await screen.findByText('Try again');
  expect(container.querySelector('.status-message--failure')).not.toBeNull();
});

test('Verify defaults to a waiting state', () => {
  const { container } = render(<Verify {...makeProps()}/>);
  expect(container.querySelector('.status-message--loading')).not.toBeNull();
});

test('Verify renders the thumbnail from the method', () => {
  const { container } = render(<Verify {...makeProps()}/>);
  expect(container.querySelector('.mfa-verification-container__thumbnail')).not.toBeNull();
});

test('Verify does not render actions when in the success state', async () => {
  const { container } = render(<Verify {...makeProps()}/>);
  resolveVerification();
  await screen.findByText('Logging in...');
  expect(container.querySelector('.mfa-action-list__item')).toBeNull();
});

test('Verify renders a retry button when in a failure state', async () => {
  const { container } = render(<Verify {...makeProps()}/>);
  rejectVerification();
  await screen.findByText('Try again');
  expect(container.querySelector('.mfa-action-list__item').textContent).toBe('Try again');
});

test('Verify renders only the "moreOptionsControl" prop provided when in waiting state', () => {
  const { container } = render(
    <Verify {...makeProps({
      moreOptionsControl: <div className="test-more-options">Hello world</div>
    })}
    />
  );
  expect(container.querySelector('.test-more-options').textContent).toBe('Hello world');
});
