import Injector from 'lib/Injector';
import WebAuthnRegister from 'components/WebAuthn/Register';
import WebAuthnVerify from 'components/WebAuthn/Verify';

export default () => {
  Injector.component.registerMany({
    WebAuthnRegister,
    WebAuthnVerify,
  });
};
