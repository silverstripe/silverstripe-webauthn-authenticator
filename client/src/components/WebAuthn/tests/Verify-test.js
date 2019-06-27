/* global jest, describe, it, each, expect */

import Verify from '../Verify';

jest.mock('lib/Injector');

const auth = require('lib/auth');

jest.unmock('lib/auth');

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
  description: 'Verify using a security key',
  supportLink: 'https://google.com',
  component: 'Verify',
  thumbnail: '/foo/bar.jpg',
};

const onCompleteVerificationMock = jest.fn();
auth.performVerification = jest.fn();

describe('Verify', () => {
  beforeEach(() => {
    onCompleteVerificationMock.mockReset();
    auth.performVerification.mockClear();
    auth.performVerification.mockReturnValue(Promise.resolve(true));
  });

  describe('handleRetry()', () => {
    it('clears failure state', done => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      wrapper.instance().setState({ failure: true }, () => {
        wrapper.instance().handleRetry(new Event('test'));
        expect(wrapper.instance().state.failure).toBe(false);
        done();
      });
    });
  });

  describe('startAuth()', () => {
    it('performs verification then calls onCompleteVerification on success', done => {
      shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      expect(auth.performVerification).toHaveBeenCalled();
      setTimeout(() => {
        expect(onCompleteVerificationMock).toHaveBeenCalled();
        done();
      }, 1050); // default delay is 1000ms
    });
  });

  describe('renderDescription()', () => {
    it('renders the instructions', () => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      expect(wrapper.text()).toContain('Use your security key to verify your identity');
    });

    it('renders the help link when one is provided', () => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      expect(wrapper.text()).toContain('How to use security keys');
    });

    it('does not render the help link when one is not provided', () => {
      const wrapper = shallow(
        <Verify
          method={{
            ...mockMethod,
            supportLink: undefined,
          }}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      expect(wrapper.text()).not.toContain('How to use security keys');
    });
  });

  describe('renderStatus()', () => {
    it('handles provided errors as props', () => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          errors={['I am a test', 'Hello world']}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      expect(wrapper.find('.status-message--error')).toHaveLength(1);
      // Ensure the provided messages are rendered
      expect(wrapper.text()).toContain('I am a test');
      expect(wrapper.text()).toContain('Hello world');
    });

    it('handles a success state', done => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      wrapper.instance().setState({ success: true }, () => {
        expect(wrapper.find('.status-message--success')).toHaveLength(1);
        done();
      });
    });

    it('handles a failure state', done => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      wrapper.instance().setState({ failure: true }, () => {
        expect(wrapper.find('.status-message--failure')).toHaveLength(1);
        done();
      });
    });

    it('defaults to a waiting state', () => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      expect(wrapper.find('.status-message--loading')).toHaveLength(1);
    });
  });

  describe('renderThumbnail()', () => {
    it('renders the thumbnail from the method', () => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      const container = wrapper.find('.mfa-verification-container__thumbnail');
      expect(container).toHaveLength(1);
    });
  });

  describe('renderActions()', () => {
    it('returns none when in the success state', done => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );
      wrapper.instance().setState({ success: true }, () => {
        const container = wrapper.find('.mfa-verification-container__actions');
        expect(container).toHaveLength(1);
        expect(container.children()).toHaveLength(0);
        done();
      });
    });

    it('renders a retry button when in a failure state', done => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );
      wrapper.instance().setState({ failure: true }, () => {
        const container = wrapper.find('.mfa-verification-container__actions');
        expect(container).toHaveLength(1);
        expect(container.find('button')).toHaveLength(1);
        done();
      });
    });

    it('renders only the "moreOptionsControl" prop provided when in waiting state', () => {
      const wrapper = shallow(
        <Verify
          method={mockMethod}
          moreOptionsControl={() => 'Hello world'}
          onCompleteVerification={onCompleteVerificationMock}
        />
      );

      const container = wrapper.find('.mfa-verification-container__actions');
      expect(container).toHaveLength(1);
      expect(container.children()).toHaveLength(1);
    });
  });
});
