import {PhysicsBlock} from "physicsBlock";

export class Collider {
	public static processCollisions(collidables: PhysicsBlock[]): void {
		if (collidables.length <= 1) {
			// Need multiple objects to perform collisions
			return;
		}

		for (let i: number = 0; i < collidables.length - 1; i++) {
			let collisionAction: (subject: PhysicsBlock, newYSpeed: number) => void = (subject: PhysicsBlock, newYSpeed: number) => {
				subject.VerticalBounce(newYSpeed);
			};

			let subject: PhysicsBlock = collidables[i];

			for (let j: number = i + 1; j < collidables.length; j++) {
				let target: PhysicsBlock = collidables[j];

				let isVerticalOverlap: boolean = (subject.top < target.bottom) && (subject.bottom > target.top);
				let isHorizontalOverlap: boolean = (subject.left < target.right) && (subject.right > target.left);

				if (isVerticalOverlap && isHorizontalOverlap) {
					// Always simulate a vertical bounce
					// If masses are the same speed can be swapped during an elastic collision
					let subjectYSpeed: number = subject.ySpeed;
					let targetYSpeed: number = target.ySpeed;
					collisionAction(subject, targetYSpeed);
					collisionAction(target, subjectYSpeed);

					// Only simulate a horizontal bound if the x overlap has just started
					let subjectPreviousLeft: number = subject.xPosition - subject.xSpeed;
					let subjectPreviousRight: number = subjectPreviousLeft + subject.width;
					let targetPreviousLeft: number = target.xPosition - target.xSpeed;
					let targetPreviousRight: number = targetPreviousLeft + target.width;

					let wasHorizontalOverlap: boolean =
						(subjectPreviousLeft < targetPreviousRight)
						&& (subjectPreviousRight > targetPreviousLeft);

					if (!wasHorizontalOverlap) {
						subject.xSpeed = -subject.xSpeed;
						target.xSpeed = -target.xSpeed;
					}
				}
			}
		}
	}
}
