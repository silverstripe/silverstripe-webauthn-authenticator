import Injector from 'lib/Injector';
import WebAuthnRegister from 'components/Register';
import WebAuthnLogin from 'components/Login';

export default () => {
  Injector.component.registerMany({
    WebAuthnRegister,
    WebAuthnLogin,
  });
};
