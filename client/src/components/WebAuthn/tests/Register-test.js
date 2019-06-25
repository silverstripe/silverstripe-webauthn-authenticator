/* global jest, describe, it, expect */

import React from 'react';
import Enzyme, { shallow } from 'enzyme';
import Adapter from 'enzyme-adapter-react-16';
import { Component as Register } from '../Register';

Enzyme.configure({ adapter: new Adapter() });

window.ss = {
  i18n: {
    _t: (key, string) => string,
    inject: (template) => template,
  },
};

const mockMethod = {
  urlSegment: 'web-authn',
  name: 'Security key',
  description: 'Register using a security key',
  supportLink: 'https://google.com',
  component: 'WebAuthnRegister',
};

const onBackMock = jest.fn();
const onCompleteRegistrationMock = jest.fn();

describe('Register', () => {
  beforeEach(() => {
    onBackMock.mockReset();
    onCompleteRegistrationMock.mockReset();
  });

  describe('renderActions()', () => {
    it('does not render any actions when a backend error has occurred', () => {
      const wrapper = shallow(
        <Register
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
          method={mockMethod}
          errors={['I am a unit test']}
        />
      );

      expect(wrapper.find('.mfa-registration-container__actions').children()).toHaveLength(0);
    });
  });

  describe('renderStatus()', () => {
    it('detects errors and renders them', () => {
      const wrapper = shallow(
        <Register
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
          method={mockMethod}
          errors={['I am a unit test', 'Something went wrong']}
        />
      );

      expect(wrapper.text()).toContain('I am a unit test');
      expect(wrapper.text()).toContain('Something went wrong');
    });
  });
});
