import Injector from 'lib/Injector';
import WebAuthnRegister from 'components/WebAuthn/Register';
import WebAuthnLogin from 'components/WebAuthn/Login';

export default () => {
  Injector.component.registerMany({
    WebAuthnRegister,
    WebAuthnLogin,
  });
};
