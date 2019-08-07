import {Renderer} from "renderer";
import {Controller} from "controller";

let canvas: HTMLCanvasElement = document.getElementById("viewport") as HTMLCanvasElement;

let controller: Controller = new Controller(canvas);

new Renderer(canvas, controller).Start();

// Ensure keyboard events when loaded in an iframe (fix for itch.io)
window.onload = function(): void {
	window.focus();
};
window.onclick = function(): void {
	window.focus();
};
