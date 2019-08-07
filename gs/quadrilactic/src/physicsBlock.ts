import {Block} from "block";
import {MovingPoint, Point} from "point";
import {Renderable} from "renderable";
import {Sound} from "sound";
import {Volume} from "volume";

export class PhysicsBlock extends Block {

	private internalGravity: number;
	private onBounceCallback: () => void;
	private worldWidth: number;

	private rebound: Sound;

	public get gravity(): number {
		return this.internalGravity;
	}
	public set gravity(newValue: number) {
		this.internalGravity = newValue;
	}

	get onBounce(): () => void {
		return this.onBounceCallback;
	}
	set onBounce(newValue: () => void) {
		this.onBounceCallback = newValue;
	}

	public constructor(
		worldPosition: MovingPoint,
		dimensions: Point,
		color: string,
		gravity: number,
		volume: Volume,
		xSpeedLimit: number,
		worldWidth?: number
	) {
		super(worldPosition, dimensions, color, xSpeedLimit);

		this.internalGravity = gravity;
		this.worldWidth = worldWidth;

		this.rebound = volume.createSound("snd/blip.wav", {});
	}

	public Tick(deltaTime: number): void {
		super.Tick(deltaTime);

		// If off the right, bounce left
		if (this.right > this.worldWidth) {
			this.rebound.play();

			// Clamp on screen, invert horizontal speed
			this.skew += 3;
			this.xPosition = this.worldWidth - this.width;
			this.xSpeed = -Math.abs(this.xSpeed);
		}

		// If off the left, bounce right
		if (this.left < 0) {
			this.rebound.play();

			// Clamp on screen, invert horizontal speed
			this.xPosition = 0;
			this.skew += 3;
			this.xSpeed = Math.abs(this.xSpeed);
		}

		// Apply acceleration due to gravity
		this.ySpeed += (this.internalGravity * deltaTime);
	}

	public Render(renderContext: CanvasRenderingContext2D): Renderable[] {
		return super.Render(renderContext);
	}

	public VerticalBounce(newYSpeed: number): void {
		this.ySpeed = newYSpeed;

		this.skew += 10;

		// Allow insertion of bouncing code
		if (this.onBounceCallback) {
			this.onBounceCallback();
		}
	}

	public Reset(): void {
		super.Reset();
	}
}
