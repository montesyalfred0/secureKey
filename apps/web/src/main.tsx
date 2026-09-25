import { render } from 'preact';
import { App } from './app.js';
import './styles.css';

const root = document.getElementById('app');
if (root === null) {
  throw new Error('No se encontro el contenedor #app');
}

render(<App />, root);
