import {Controller} from "controller";
import {PhysicsBlock} from "physicsBlock";
import {MovingPoint, Point, Rectangle} from "point";
import {Renderable} from "renderable";
import {Sprite} from "sprite";
import {Sound} from "sound";
import {Volume} from "volume";
import {Particle} from "particle";

export class Player extends PhysicsBlock {
	private static jumpSpeedIncrease: number = -8;
	private static degrees: number = Math.PI / 180;
	private static jumpRotationSlowDown: number = 0.1;
	private static initialJumpRotationSpeed: number = 15;
	private static horizontalSpeedIncrease: number = 0.5;
	private static faceSwapThreshold: number = 3.5;

	private isJumping: boolean;
	private jumpRotationAmount: number;
	private jumpRotationSpeed: number;
	private controller: Controller;

	private jump: Sound;
	private bounce: Sound;
	private faceUp: Sprite;
	private faceDown: Sprite;
	private faceHover: Sprite;

	public constructor(
		worldPosition: MovingPoint,
		dimensions: Point,
		color: string,
		controller: Controller,
		gravity: number,
		worldWidth: number,
		volume: Volume
	) {
		super(worldPosition, dimensions, color, gravity, volume, 7, worldWidth);

		this.onBounce = this.Bounce;

		this.controller = controller;
		this.isJumping = false;
		this.jumpRotationAmount = 0;

		this.faceUp = new Sprite("img/faceHappy.png", dimensions);
		this.faceDown = new Sprite("img/faceWorried.png", dimensions);
		this.faceHover = new Sprite("img/faceChill.png", dimensions);

		this.jump = volume.createSound("snd/jump.wav", {});
		this.bounce = volume.createSound("snd/blip3.wav", {});
	}

	public Tick(deltaTime: number): void {
		super.Tick(deltaTime);

		// Perform the jump
		if (!this.isJumping && this.controller.isKeyPressed(["up", "space", "w"])) {
			this.jump.play();
			this.ySpeed = Player.jumpSpeedIncrease * deltaTime;
			this.isJumping = true;
			this.jumpRotationSpeed = this.direction === "right" ? Player.initialJumpRotationSpeed : -Player.initialJumpRotationSpeed;
		}

		// Allow influence over horizontal direction
		if (this.controller.isKeyPressed(["left", "a"])) {
			this.xSpeed -= (Player.horizontalSpeedIncrease * deltaTime);
		}
		if (this.controller.isKeyPressed(["right", "d"])) {
			this.xSpeed += (Player.horizontalSpeedIncrease * deltaTime);
		}

		// Apply jump rotation
		this.jumpRotationAmount += (this.jumpRotationSpeed * deltaTime);
		if (this.jumpRotationSpeed > 0) {
			this.jumpRotationSpeed = Math.max(0, this.jumpRotationSpeed - Player.jumpRotationSlowDown);
		} else if (this.jumpRotationSpeed < 0) {
			this.jumpRotationSpeed = Math.min(0, this.jumpRotationSpeed + Player.jumpRotationSlowDown);
		}

		this.jumpRotationAmount += this.xSpeed / 2;
	}

	public Bounce(): void {
		// If we were jumping, thats over now
		this.isJumping = false;
		this.jumpRotationAmount = 0;
		this.jumpRotationSpeed = 0;
		this.bounce.play();
	}

	public Render(renderContext: CanvasRenderingContext2D): Renderable[] {
		renderContext.save();

		renderContext.translate(this.centerXPosition, this.centerYPosition);
		renderContext.rotate(this.jumpRotationAmount * Player.degrees);
		renderContext.translate(-this.centerXPosition, -this.centerYPosition);

		let faceSprite: Sprite;

		if (this.ySpeed > Player.faceSwapThreshold) {
			faceSprite = this.faceDown;
		} else if (this.ySpeed < -Player.faceSwapThreshold) {
			faceSprite = this.faceUp;
		} else {
			faceSprite = this.faceHover;
		}

		let xHexidecimal: string = Math.max(Math.round(15 - Math.abs(this.xSpeed)), 0).toString(16);
		let yHexidecimal: string = Math.max(Math.round(15 - Math.abs(this.ySpeed)), 0).toString(16);

		this.fillColor = "#" + yHexidecimal + yHexidecimal + "ff" + xHexidecimal + xHexidecimal;

		let newRenderables: Renderable[] = super.Render(renderContext);

		newRenderables.forEach((renderable: Renderable) => {
			(renderable as Particle).rotation = this.jumpRotationAmount;
		});

		renderContext.restore();

		renderContext.save();
		renderContext.translate(this.centerXPosition, this.centerYPosition);
		renderContext.rotate(this.jumpRotationAmount * Player.degrees);
		renderContext.translate(-this.centerXPosition, -this.centerYPosition);

		let skewedPosition: Rectangle = this.skewedPosition;

		renderContext.translate(skewedPosition.x, skewedPosition.y);

		faceSprite.dimensions = {
			x: skewedPosition.width,
			y: skewedPosition.height
		};

		newRenderables = newRenderables.concat(faceSprite.Render(renderContext));

		renderContext.restore();

		return newRenderables;
	}

	public Reset(): void {
		super.Reset();

		this.isJumping = false;
		this.jumpRotationAmount = 0;
		this.jumpRotationSpeed = 0;
	}
}
