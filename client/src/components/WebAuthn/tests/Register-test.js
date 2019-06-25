/* global jest, describe, it, each, expect */

import Register, { VIEWS } from '../Register';

jest.mock('lib/Injector');

const auth = require('lib/auth');

jest.unmock('lib/auth');

// eslint-disable-next-line no-unused-vars
import fetch from 'isomorphic-fetch';
import React from 'react';
import Enzyme, { shallow } from 'enzyme';
import Adapter from 'enzyme-adapter-react-16';

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
auth.performRegistration = jest.fn();

describe('Register', () => {
  beforeEach(() => {
    onBackMock.mockReset();
    onCompleteRegistrationMock.mockReset();
    auth.performRegistration.mockClear();
  });

  describe('handleBack()', () => {
    it('triggers the onBack callback', () => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().handleBack();

      expect(onBackMock).toHaveBeenCalled();
    });
  });

  describe('handleNext()', () => {
    it('does not trigger onCompleteRegistration when registrationData is unavailable', () => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().handleNext();

      expect(onCompleteRegistrationMock).not.toHaveBeenCalled();
    });


    it('trigger onCompleteRegistration when registrationData is available', () => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().setState({ registrationData: {} });

      wrapper.instance().handleNext();

      expect(onCompleteRegistrationMock).toHaveBeenCalledWith({});
    });
  });

  describe('handleStartRegistration()', () => {
    it('changes the view to REGISTERING when called', () => {
      auth.performRegistration.mockImplementation(() => Promise.resolve({}));

      const wrapper = shallow(
        <Register
          method={{}}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().handleStartRegistration();

      expect(wrapper.instance().state.view).toEqual(VIEWS.REGISTERING);
    });

    it('changes the view to SUCCESS when complete', (complete) => {
      auth.performRegistration.mockImplementation(() => Promise.resolve({}));

      const wrapper = shallow(
        <Register
          method={{}}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().handleStartRegistration();

      // Wait for promise to resolve
      setTimeout(() => {
        expect(wrapper.instance().state.view).toEqual(VIEWS.SUCCESS);
        complete();
      }, 50);
    });

    it('changes the view to FAILURE when an error is encountered', (complete) => {
      auth.performRegistration.mockImplementation(() => Promise.reject('Failure'));

      const wrapper = shallow(
        <Register
          method={{}}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().handleStartRegistration();

      // Wait for promise to resolve
      setTimeout(() => {
        expect(wrapper.instance().state.view).toEqual(VIEWS.FAILURE);
        complete();
      }, 50);
    });
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

    it('renders a disabled register button and a back button when loading', () => {
      const wrapper = shallow(
        <Register
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
          method={mockMethod}
        />
      );

      const actions = wrapper.find('.mfa-registration-container__actions').children();

      expect(actions).toHaveLength(2);
      expect(actions.at(0).text()).toContain('Register');
      expect(actions.at(0).is('[disabled=true]')).toBeTruthy();
      expect(actions.at(1).text()).toContain('Back');
      expect(actions.at(1).is('[disabled=false]')).toBeTruthy();
    });

    it('renders a register and back button when ready', (complete) => {
      const wrapper = shallow(
        <Register
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
          method={mockMethod}
        />
      );

      wrapper.instance().setState({ view: VIEWS.READY }, () => {
        const actions = wrapper.find('.mfa-registration-container__actions').children();

        expect(actions).toHaveLength(2);
        expect(actions.at(0).text()).toContain('Register');
        expect(actions.at(0).is('[disabled=false]')).toBeTruthy();
        expect(actions.at(1).text()).toContain('Back');
        expect(actions.at(1).is('[disabled=false]')).toBeTruthy();

        complete();
      });
    });

    it('renders disabled registering and back buttons during registration', (complete) => {
      const wrapper = shallow(
        <Register
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
          method={mockMethod}
        />
      );

      wrapper.instance().setState({ view: VIEWS.REGISTERING }, () => {
        const actions = wrapper.find('.mfa-registration-container__actions').children();

        expect(actions).toHaveLength(2);
        expect(actions.at(0).text()).toContain('Registering');
        expect(actions.at(0).is('[disabled=true]')).toBeTruthy();
        expect(actions.at(1).text()).toContain('Back');
        expect(actions.at(1).is('[disabled=true]')).toBeTruthy();

        complete();
      });
    });

    it('renders complete registration button when registration succeeds', (complete) => {
      const wrapper = shallow(
        <Register
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
          method={mockMethod}
        />
      );

      wrapper.instance().setState({ view: VIEWS.SUCCESS }, () => {
        const actions = wrapper.find('.mfa-registration-container__actions').children();

        expect(actions).toHaveLength(1);
        expect(actions.at(0).text()).toContain('Complete registration');
        expect(actions.at(0).is('[disabled=false]')).toBeTruthy();

        complete();
      });
    });

    it('renders retry and back buttons when registration fails', (complete) => {
      const wrapper = shallow(
        <Register
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
          method={mockMethod}
        />
      );

      wrapper.instance().setState({ view: VIEWS.FAILURE }, () => {
        const actions = wrapper.find('.mfa-registration-container__actions').children();

        expect(actions).toHaveLength(2);
        expect(actions.at(0).text()).toContain('Retry');
        expect(actions.at(0).is('[disabled=false]')).toBeTruthy();
        expect(actions.at(1).text()).toContain('Back');
        expect(actions.at(1).is('[disabled=false]')).toBeTruthy();

        complete();
      });
    });
  });

  describe('renderStatus()', () => {
    it('displays error messages if present', () => {
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

    it('displays waiting message when the view is loading', (complete) => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().setState({ view: VIEWS.LOADING }, () => {
        const message = wrapper.find('.status-message--loading');

        expect(message).toHaveLength(1);
        expect(message.text()).toContain('Waiting');
        complete();
      });
    });

    it('displays no message when the view is ready', (complete) => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().setState({ view: VIEWS.READY }, () => {
        const message = wrapper.find('.status-message--empty');

        expect(message).toHaveLength(1);
        complete();
      });
    });

    it('displays waiting message during registration', (complete) => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().setState({ view: VIEWS.REGISTERING }, () => {
        const message = wrapper.find('.status-message--loading');

        expect(message).toHaveLength(1);
        expect(message.text()).toContain('Waiting');
        complete();
      });
    });

    it('displays complete message when the registration is successful', (complete) => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().setState({ view: VIEWS.SUCCESS }, () => {
        const message = wrapper.find('.status-message--success');

        expect(message).toHaveLength(1);
        expect(message.text()).toContain('Key verified');
        complete();
      });
    });

    it('displays error message when the registration fails', (complete) => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      wrapper.instance().setState({ view: VIEWS.FAILURE }, () => {
        const message = wrapper.find('.status-message--failure');

        expect(message).toHaveLength(1);
        expect(message.text()).toContain('Something went wrong');
        complete();
      });
    });
  });

  describe('render()', () => {
    it('renders the full UI', () => {
      const wrapper = shallow(
        <Register
          method={mockMethod}
          onBack={onBackMock}
          onCompleteRegistration={onCompleteRegistrationMock}
        />
      );

      expect(wrapper.find('.mfa-registration-container__description')).toHaveLength(1);
      expect(wrapper.find('.mfa-registration-container__status')).toHaveLength(1);
      expect(wrapper.find('.mfa-registration-container__thumbnail')).toHaveLength(1);
      expect(wrapper.find('.mfa-registration-container__actions')).toHaveLength(1);
    });
  });

  it('renders with the READY view if keyData is provided immediately', () => {
    const wrapper = shallow(
      <Register
        method={mockMethod}
        onBack={onBackMock}
        onCompleteRegistration={onCompleteRegistrationMock}
        keyData={{ data: true }}
      />
    );

    expect(wrapper.instance().state.view).toEqual(VIEWS.READY);
  });

  it('transitions from LOADING to READY view when keyData is provided', (complete) => {
    const wrapper = shallow(
      <Register
        method={mockMethod}
        onBack={onBackMock}
        onCompleteRegistration={onCompleteRegistrationMock}
      />
    );

    expect(wrapper.instance().state.view).toEqual(VIEWS.LOADING);

    wrapper.setProps({ keyData: { data: true } }, () => {
      expect(wrapper.instance().state.view).toEqual(VIEWS.READY);
      complete();
    });
  });
});
