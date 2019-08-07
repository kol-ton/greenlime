import {Point} from "point";

export class Controller {
	private static keyCodes: { [keyCode: number]: string } = {
		13: "enter",
		32: "space",
		37: "left",
		38: "up",
		39: "right",
		65: "a",
		68: "d",
		69: "e",
		77: "m",
		86: "v",
		87: "w"
	};

	private isKeyPressedState: { [keyName: string]: boolean } = {
		"enter": false,
		"space": false,
		"left": false,
		"up": false,
		"right": false,
		"a": false,
		"d": false,
		"e": false,
		"m": false,
		"v": false,
		"w": false
	};

	private mousePosition: Point;

	private clickLocation: Point;

	private canvas: HTMLCanvasElement;

	constructor(canvas: HTMLCanvasElement) {
		this.canvas = canvas;

		window.addEventListener("keyup", (event: KeyboardEvent) => {
			this.handleKeyUp(event);
		});

		window.addEventListener("keydown", (event: KeyboardEvent) => {
			this.handleKeyDown(event);

			// Prevent known key codes executing their default action.
			if (Controller.keyCodes[event.keyCode]) {
				event.preventDefault();
			}
		});

		canvas.addEventListener("mousemove", (event: MouseEvent) => {
			this.handleMouseMove(event);
		});

		canvas.addEventListener("mousedown", (event: MouseEvent) => {
			this.handleMouseDown(event);
		});
	}

	public isKeyPressed(key: string | string[]): boolean {
		let keys: string[] = [].concat(key);
		return keys.some((value: string) => {
			return this.isKeyPressedState[value];
		});
	}

	public getMousePosition(): Point {
		return this.mousePosition;
	}

	public getClickPosition(): Point {
		return this.clickLocation;
	}

	public clearClick(): void {
		this.clickLocation = undefined;
	}

	private handleKeyUp(event: KeyboardEvent): void {
		let key: string = Controller.keyCodes[event.keyCode];
		this.isKeyPressedState[key] = false;
	}

	private handleKeyDown(event: KeyboardEvent): void {
		let key: string = Controller.keyCodes[event.keyCode];
		this.isKeyPressedState[key] = true;
	}

	private handleMouseMove(event: MouseEvent): void {
		let canvasElementPosition: ClientRect = this.canvas.getBoundingClientRect();
		this.mousePosition  = {
			x: event.clientX - canvasElementPosition.left,
			y: event.clientY - canvasElementPosition.top,
		};
	}

	private handleMouseDown(event: MouseEvent): void {
		let canvasElementPosition: ClientRect = this.canvas.getBoundingClientRect();
		this.clickLocation = {
			x: event.clientX - canvasElementPosition.left,
			y: event.clientY - canvasElementPosition.top,
		};

		event.preventDefault();
	}
}
